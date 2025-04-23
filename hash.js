const bcrypt = require('bcrypt');

bcrypt.hash('Dat1982004!', 10).then(hash => {
  console.log('Hash đã tạo:', hash);
});
