const nodemailer = require('nodemailer');

const sendEmail = async options => {
  // create transporter
  const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: 587,
    // secure: false, // use SSL
    auth: {
      user: process.env.EMAIL_USERNAME,
      pass: process.env.EMAIL_PASSWORD
    }
    // tls: {
    //   rejectUnauthorized: false
    // }
  });

  // defining email options
  const mailOptions = {
    from: 'Manas Kapoor <manas@mail.io>',
    to: options.email,
    subject: options.subject,
    text: options.message
  };

  // send email
  await transporter.sendMail(mailOptions);
};

module.exports = sendEmail;
