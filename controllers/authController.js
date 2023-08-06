const { promisify } = require('util');
const jwt = require('jsonwebtoken');
const User = require('./../models/userModel');
const catchAsync = require('./../utils/catchAsync');
const AppError = require('./../utils/appError');

const signToken = id => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN
  });
};

exports.signup = catchAsync(async (req, res, next) => {
  const newUser = await User.create({
    name: req.body.name,
    email: req.body.email,
    password: req.body.password,
    passwordConfirm: req.body.passwordConfirm,
    passwordChangedAt: req.body.passwordChangedAt
  });

  const token = signToken(newUser._id);

  res.status(201).json({
    status: 'success',
    token,
    data: {
      user: newUser
    }
  });
});

exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;

  // 1) if mail pass exists
  if (!email || !password) {
    return next(new AppError('please provide email and password!', 400));
  }
  // 2) if mail pass are correct
  const user = await User.findOne({ email }).select('+password');

  if (!user || !(await user.correctPassword(password, user.password))) {
    return next(new AppError('incorrect email or password!', 401));
  }

  // console.log(user);

  // 3) if all ok send token
  const token = signToken(user._id);
  res.status(200).json({
    status: 'success',
    token
  });
});

exports.protect = catchAsync(async (req, res, next) => {
  //1) getting token
  let token;
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    token = req.headers.authorization.split(' ')[1];
  }

  if (!token) {
    return next(new AppError('You are not logged in! Please log in', 401));
  }

  // 2) verifying token
  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  // 3) check if user still exists
  const currentUser = await User.findById(decoded.id);
  if (!currentUser) {
    return next(new AppError('The user belonging to this token DNE', 401));
  }

  // 4) check if password has been changed after token is issued
  if (currentUser.changedPasswordAfter(decoded.iat)) {
    return next(
      new AppError('Password has been changed! Please login again!', 401)
    );
  }

  //grant access to protected route
  req.user = currentUser;
  next();
});

// exports.restrictTo = (...roles) => {
//   return (req, res, next) => {
//     // roles ['admin', 'lead-guide']
//     if(!roles.includes(req.user.role)){
//       return next(new AppError('You dont have the permission '))
//     }
//   };
// };
