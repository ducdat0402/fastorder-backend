const bcrypt = require('bcrypt');

// Mật khẩu đã lưu trong database (đã hash)
const hashedPassword = '$2b$10$6.L1BDVN0BExpmopSZo3ZekSrXoIDpSq3JtZfz.k7H3fY7d7akFP6d';

// Mật khẩu người dùng nhập
const userPassword = 'password123';

bcrypt.compare(userPassword, hashedPassword)
  .then(result => {
    if (result) {
      console.log('✅ Mật khẩu đúng!');
    } else {
      console.log('❌ Mật khẩu sai!');
    }
  })
  .catch(err => {
    console.error('❗ Lỗi:', err);
  });