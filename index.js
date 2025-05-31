require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cloudinary = require('cloudinary').v2;
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');

const app = express();

// Cho phép CORS từ web (React)
app.use(cors({
  origin: ['http://localhost:3000','http://localhost:3001', 'https://fastorder.vercel.app','https://sandbox.vnpayment.vn']
}));
app.use(express.json());

// Rate limiting middleware
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 phút
  max: 100, // Giới hạn 100 request mỗi IP trong 15 phút
  message: 'Too many requests from this IP, please try again later.',
});
app.use(limiter); // Áp dụng rate limiting cho tất cả các API


// Kết nối MySQL
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

// Kiểm tra kết nối MySQL
db.getConnection()
  .then(() => console.log('Connected to MySQL'))
  .catch(err => console.error('MySQL connection error:', err));

// Cấu hình Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Middleware xác thực JWT
const authMiddleware = async (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'No token provided' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// API kiểm tra server
app.get('/', (req, res) => {
  res.json({ message: 'FastOrder API is running' });
});

// API đăng ký
app.post('/api/register', async (req, res) => {
  const { name, email, password, phone } = req.body;
  try {
    // Kiểm tra email đã tồn tại
    const [existing] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
    if (existing.length > 0) {
      return res.status(400).json({ error: 'Email already exists' });
    }

    // Mã hóa mật khẩu
    const hash = await bcrypt.hash(password, 10);

    // Thêm người dùng mới
    const [result] = await db.query(
      'INSERT INTO users (name, email, password, phone, role) VALUES (?, ?, ?, ?, ?)',
      [name, email, hash, phone, 'customer']
    );

    // Tạo JWT token
    const token = jwt.sign(
      { id: result.insertId, role: 'customer' },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );

    // Trả về token và thông tin người dùng
    res.json({
      token,
      user: { id: result.insertId, name, email, phone, role: 'customer' }
    });
  } catch (err) {
    console.error('Error in /register:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// API đăng nhập
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    // Tìm người dùng
    const [users] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
    const user = users[0];
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Kiểm tra mật khẩu
    if (await bcrypt.compare(password, user.password)) {
      // Tạo JWT token
      const token = jwt.sign(
        { id: user.id, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: '1d' }
      );
      res.json({
        token,
        user: { id: user.id, name: user.name, email: user.email, role: user.role }
      });
    } else {
      res.status(401).json({ error: 'Invalid email or password' });
    }
  } catch (err) {
    console.error('Error in /login:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// API lấy danh sách món ăn
app.get('/api/foods', async (req, res) => {
  try {
    const { category_id } = req.query;
    let query = 'SELECT f.*, c.name as category_name FROM food f JOIN categories c ON f.category_id = c.id WHERE f.is_available = ?';
    const params = [true];

    if (category_id) {
      query += ' AND f.category_id = ?';
      params.push(category_id);
    }

    const [foods] = await db.query(query, params);
    res.json(foods);
  } catch (err) {
    console.error('Error in /foods:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// API lấy danh sách danh mục
app.get('/api/categories', async (req, res) => {
  try {
    const [categories] = await db.query('SELECT * FROM categories');
    res.json(categories);
  } catch (err) {
    console.error('Error in /categories:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// API tạo danh mục mới (admin only)
app.post('/api/categories', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  const { name } = req.body;
  if (!name) {
    return res.status(400).json({ error: 'Category name is required' });
  }

  try {
    const [result] = await db.query('INSERT INTO categories (name) VALUES (?)', [name]);
    res.json({ id: result.insertId, name });
  } catch (err) {
    console.error('Error in /categories (POST):', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// API tạo món ăn mới (admin only)
app.post('/api/foods', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  const { name, description, price, img_url, is_available, category_id } = req.body;
  if (!name || !price || !category_id) {
    return res.status(400).json({ error: 'Name, price, and category_id are required' });
  }

  try {
    const [result] = await db.query(
      'INSERT INTO food (name, description, price, img_url, is_available, category_id) VALUES (?, ?, ?, ?, ?, ?)',
      [name, description || null, price, img_url || null, is_available !== undefined ? is_available : true, category_id]
    );
    res.json({ id: result.insertId, name, description, price, img_url, is_available, category_id });
  } catch (err) {
    console.error('Error in /foods (POST):', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// API cập nhật món ăn (admin only)
app.put('/api/foods/:id', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  const { id } = req.params;
  const { name, description, price, img_url, is_available, category_id } = req.body;
  if (!name || !price || !category_id) {
    return res.status(400).json({ error: 'Name, price, and category_id are required' });
  }

  try {
    const [result] = await db.query(
      'UPDATE food SET name = ?, description = ?, price = ?, img_url = ?, is_available = ?, category_id = ? WHERE id = ?',
      [name, description || null, price, img_url || null, is_available, category_id, id]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Food not found' });
    }
    res.json({ id, name, description, price, img_url, is_available, category_id });
  } catch (err) {
    console.error('Error in /foods/:id (PUT):', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// API xóa món ăn (admin only)
app.delete('/api/foods/:id', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  const { id } = req.params;
  try {
    const [result] = await db.query('DELETE FROM food WHERE id = ?', [id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Food not found' });
    }
    res.json({ message: 'Food deleted successfully' });
  } catch (err) {
    console.error('Error in /foods/:id (DELETE):', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// API đặt đơn hàng
app.post('/api/orders', authMiddleware, async (req, res) => {
  const { items } = req.body;
  const user_id = req.user.id;

  if (!items || !Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'Items are required' });
  }

  try {
    let total_price = 0;
    const itemsWithPrice = []; // Lưu danh sách món kèm giá để chèn vào order_items

    // Lấy giá của từng món và tính tổng giá
    for (const item of items) {
      const [foods] = await db.query('SELECT price FROM food WHERE id = ?', [item.food_id]);
      if (!foods[0]) {
        return res.status(404).json({ error: `Food with id ${item.food_id} not found` });
      }
      const unit_price = foods[0].price;
      total_price += unit_price * item.quantity;
      itemsWithPrice.push({ ...item, unit_price }); // Lưu giá vào danh sách
    }

    // Tạo đơn hàng
    const [order] = await db.query(
      'INSERT INTO orders (user_id, total_price, status, created_at) VALUES (?, ?, ?, NOW())',
      [user_id, total_price, 'pending']
    );

    // Chèn các mục vào order_items, bao gồm unit_price
    for (const item of itemsWithPrice) {
      await db.query(
        'INSERT INTO order_items (order_id, food_id, quantity, unit_price) VALUES (?, ?, ?, ?)',
        [order.insertId, item.food_id, item.quantity, item.unit_price]
      );
    }

    // Tạo ticket
    const ticket_code = require('crypto').randomBytes(8).toString('hex');
    await db.query(
      'INSERT INTO tickets (order_id, ticket_code, issued_at, is_used) VALUES (?, ?, NOW(), ?)',
      [order.insertId, ticket_code, false]
    );
    // Ghi log hành động
    console.log(`User ${user_id} placed order ${order.insertId} with total price: ${total_price}`);
    res.json({ order_id: order.insertId, total_price, status: 'pending', ticket_code });
  } catch (err) {
    console.error('Error in /orders (POST):', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/tickets/verify', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  const { ticket_code } = req.body;

  if (!ticket_code) {
    return res.status(400).json({ error: 'Ticket code is required' });
  }

  try {
    // Kiểm tra ticket và trạng thái thanh toán
    const [tickets] = await db.query(
      'SELECT t.*, p.status as payment_status ' +
      'FROM tickets t ' +
      'JOIN payments p ON t.order_id = p.order_id ' +
      'WHERE t.ticket_code = ? AND t.is_used = ?',
      [ticket_code, false]
    );

    if (!tickets[0]) {
      return res.status(400).json({ error: 'Ticket not found or already used' });
    }

    // Kiểm tra trạng thái thanh toán
    if (tickets[0].payment_status !== 'completed') {
      return res.status(400).json({ error: 'Payment not completed. Please complete payment before receiving your order.' });
    }

    // Đánh dấu ticket đã sử dụng
    await db.query('UPDATE tickets SET is_used = ? WHERE ticket_code = ?', [true, ticket_code]);

    res.json({ message: 'Ticket verified successfully', order_id: tickets[0].order_id });
  } catch (err) {
    console.error('Error in /tickets/verify:', err);
    res.status(500).json({ error: 'Server error' });
  }
});
//xác nhận thanh toán tiền mặt
app.post('/api/payments/confirm', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  const { payment_id } = req.body;

  if (!payment_id) {
    return res.status(400).json({ error: 'Payment ID is required' });
  }

  try {
    // Kiểm tra payment
    const [payments] = await db.query(
      'SELECT * FROM payments WHERE payment_id = ? AND method = ?',
      [payment_id, 'cash']
    );

    if (!payments[0]) {
      return res.status(404).json({ error: 'Payment not found or not a cash payment' });
    }

    if (payments[0].status === 'completed') {
      return res.status(400).json({ error: 'Payment already completed' });
    }

    // Cập nhật trạng thái thanh toán
    await db.query(
      'UPDATE payments SET status = ? WHERE payment_id = ?',
      ['completed', payment_id]
    );

    // Ghi log hành động
    console.log(`Admin ${req.user.id} confirmed cash payment for payment_id: ${payment_id}`);

    res.json({ message: 'Payment confirmed successfully' });
  } catch (err) {
    console.error('Error in /payments/confirm:', err);
    res.status(500).json({ error: 'Server error' });
  }
});


// API lấy lịch sử đơn hàng
app.get('/api/orders', authMiddleware, async (req, res) => {
  try {
    // Lấy danh sách đơn hàng của người dùng
    const [orders] = await db.query(
      'SELECT o.*, t.ticket_code FROM orders o LEFT JOIN tickets t ON o.id = t.order_id WHERE o.user_id = ?',
      [req.user.id]
    );

    // Lấy chi tiết các mục trong từng đơn hàng
    for (const order of orders) {
      const [items] = await db.query(
        'SELECT oi.*, f.name FROM order_items oi JOIN food f ON oi.food_id = f.id WHERE oi.order_id = ?',
        [order.id]
      );
      order.items = items;
    }

    res.json(orders);
  } catch (err) {
    console.error('Error in /orders:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// API lấy tất cả đơn hàng của các khách hàng (admin only)
app.get('/api/admin/orders', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  try {
    // Lấy danh sách tất cả đơn hàng
    const [orders] = await db.query(
      'SELECT o.*, u.name as customer_name FROM orders o JOIN users u ON o.user_id = u.id'
    );

    // Lấy chi tiết các mục trong từng đơn hàng
    for (const order of orders) {
      const [items] = await db.query(
        'SELECT oi.*, f.name FROM order_items oi JOIN food f ON oi.food_id = f.id WHERE oi.order_id = ?',
        [order.id]
      );
      order.items = items;
    }

    res.json(orders);
  } catch (err) {
    console.error('Error in /admin/orders:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// API tạo thanh toán
// app.post('/api/payments', authMiddleware, async (req, res) => {
//   const { order_id, method, amount } = req.body;
//   const user_id = req.user.id;

//   if (!order_id || !method || !amount) {
//     return res.status(400).json({ error: 'order_id, method, and amount are required' });
//   }

//   if (amount <= 0) {
//     return res.status(400).json({ error: 'Amount must be greater than 0' });
//   }

//   try {
//     // Kiểm tra đơn hàng có tồn tại và thuộc về user không
//     const [orders] = await db.query('SELECT * FROM orders WHERE id = ? AND user_id = ?', [order_id, user_id]);
//     if (!orders[0]) {
//       return res.status(404).json({ error: 'Order not found or not authorized' });
//     }

//     // Kiểm tra xem đơn hàng đã có thanh toán chưa
//     const [existingPayments] = await db.query('SELECT * FROM payments WHERE order_id = ?', [order_id]);
//     if (existingPayments.length > 0) {
//       return res.status(400).json({ error: 'Payment already exists for this order' });
//     }

//     // Xác định trạng thái và transaction_id dựa trên phương thức thanh toán
//     let status = 'pending';
//     let transaction_id = null;

//     if (method === 'cash') {
//       status = 'pending';
//     } else if (method === 'online') {
//       // Placeholder for online payment (PayPal will be integrated later)
//       status = 'pending'; // Sẽ cập nhật thành 'completed' sau khi tích hợp PayPal
//       transaction_id = `TXN_${Date.now()}`;
//     } else {
//       return res.status(400).json({ error: 'Invalid payment method' });
//     }

//     // Thêm bản ghi thanh toán vào database
//     const [result] = await db.query(
//       'INSERT INTO payments (order_id, method, amount, status, transaction_id, created_at) VALUES (?, ?, ?, ?, ?, NOW())',
//       [order_id, method, amount, status, transaction_id]
//     );

//     // Cập nhật trạng thái đơn hàng
//     const newOrderStatus = method === 'online' ? 'completed' : 'confirmed';
//     await db.query('UPDATE orders SET status = ? WHERE id = ?', [newOrderStatus, order_id]);

//     // Tạo ticket nếu chưa có
//     const [tickets] = await db.query('SELECT * FROM tickets WHERE order_id = ?', [order_id]);
//     if (tickets.length === 0) {
//       const ticket_code = `TICKET_${order_id}_${Date.now()}`;
//       await db.query(
//         'INSERT INTO tickets (order_id, ticket_code, issued_at) VALUES (?, ?, NOW())',
//         [order_id, ticket_code]
//       );
//     }

//     // Trả về thông tin thanh toán
//     res.json({
//       payment_id: result.insertId, // Đảm bảo result đã được khai báo
//       order_id,
//       method,
//       amount,
//       status,
//       transaction_id,
//     });
//   } catch (err) {
//     console.error('Error in /payments:', err);
//     res.status(500).json({ error: 'Server error' });
//   }
// });

// API lấy thông tin phiếu ăn
app.get('/api/tickets/:order_id', authMiddleware, async (req, res) => {
  const { order_id } = req.params;
  const user_id = req.user.id;

  try {
    const [tickets] = await db.query(
      'SELECT t.* FROM tickets t JOIN orders o ON t.order_id = o.id WHERE t.order_id = ? AND o.user_id = ?',
      [order_id, user_id]
    );
    if (!tickets[0]) {
      return res.status(404).json({ error: 'Ticket not found or not authorized' });
    }
    res.json(tickets[0]);
  } catch (err) {
    console.error('Error in /tickets/:order_id:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// API lấy chi tiết đơn hàng
app.get('/api/admin/orders/:orderId', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  const { orderId } = req.params;

  try {
    // Lấy thông tin đơn hàng
    const [orders] = await db.query(
      'SELECT o.*, u.email, u.name, t.ticket_code ' +
      'FROM orders o ' +
      'LEFT JOIN users u ON o.user_id = u.id ' +
      'LEFT JOIN tickets t ON o.id = t.order_id ' +
      'WHERE o.id = ?',
      [orderId]
    );

    if (!orders[0]) {
      return res.status(404).json({ error: 'Order not found' });
    }

    // Lấy danh sách món ăn trong đơn hàng
    const [items] = await db.query(
      'SELECT oi.*, f.name as food_name, f.price as food_price ' +
      'FROM order_items oi ' +
      'JOIN food f ON oi.food_id = f.id ' +
      'WHERE oi.order_id = ?',
      [orderId]
    );

    res.json({ order: orders[0], items });
  } catch (err) {
    console.error('Error in /admin/orders/:orderId:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/admin/foods-confirmed', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  try {
    const [foodItems] = await db.query(
      'SELECT f.name as food_name, SUM(oi.quantity) as total_quantity ' +
      'FROM order_items oi ' +
      'JOIN orders o ON oi.order_id = o.id ' +
      'JOIN food f ON oi.food_id = f.id ' +
      'WHERE o.status = ? ' +
      'GROUP BY f.id, f.name ' +
      'ORDER BY total_quantity DESC',
      ['confirmed']
    );

    res.json(foodItems);
  } catch (err) {
    console.error('Error in /admin/foods-confirmed:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// API cập nhật trạng thái đơn hàng
app.put('/api/admin/orders/:orderId/status', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  const { orderId } = req.params;
  const { status } = req.body;

  if (!['pending', 'confirmed', 'completed'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }

  try {
    const [orders] = await db.query('SELECT * FROM orders WHERE id = ?', [orderId]);
    if (!orders[0]) {
      return res.status(404).json({ error: 'Order not found' });
    }

    await db.query('UPDATE orders SET status = ? WHERE id = ?', [status, orderId]);

    // Ghi log hành động
    console.log(`Admin ${req.user.id} updated status of order ${orderId} to ${status}`);

    res.json({ message: 'Order status updated successfully' });
  } catch (err) {
    console.error('Error in /admin/orders/:orderId/status:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/payments/order/:orderId', authMiddleware, async (req, res) => {
  const { orderId } = req.params;
  const user_id = req.user.id;

  try {
    const [orders] = await db.query('SELECT * FROM orders WHERE id = ? AND user_id = ?', [orderId, user_id]);
    if (!orders[0]) {
      return res.status(404).json({ error: 'Order not found or not authorized' });
    }

    const [payments] = await db.query('SELECT * FROM payments WHERE order_id = ?', [orderId]);
    if (!payments[0]) {
      return res.status(404).json({ error: 'Payment not found for this order' });
    }

    res.json(payments[0]);
  } catch (err) {
    console.error('Error in /payments/order/:orderId:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

//hủy đơn hàng trong trạng thái đang chờ xử lý
app.delete('/api/orders/:orderId/cancel', authMiddleware, async (req, res) => {
  const { orderId } = req.params;
  const user_id = req.user.id;

  try {
    const [orders] = await db.query('SELECT * FROM orders WHERE id = ? AND user_id = ?', [orderId, user_id]);
    if (!orders[0]) {
      return res.status(404).json({ error: 'Order not found or not authorized' });
    }

    if (orders[0].status !== 'pending') {
      return res.status(400).json({ error: 'Only pending orders can be cancelled' });
    }

    // Xóa các bản ghi liên quan
    await db.query('DELETE FROM tickets WHERE order_id = ?', [orderId]);
    await db.query('DELETE FROM order_items WHERE order_id = ?', [orderId]);
    await db.query('DELETE FROM payments WHERE order_id = ?', [orderId]);
    await db.query('DELETE FROM orders WHERE id = ?', [orderId]);

    res.json({ message: 'Order cancelled successfully' });
  } catch (err) {
    console.error('Error in /orders/:orderId/cancel:', err);
    res.status(500).json({ error: 'Server error' });
  }
});


//////////////////////////////          VNPAY                  //////////////////////////////////////

// Cấu hình VNPAY


// Hàm tạo chữ ký bảo mật VNPAY
function createVnpaySignature(params, secretKey, isCallback = false) {
  let orderedKeys;

  if (isCallback) {
    // Callback từ VNPAY: Sắp xếp theo bảng chữ cái
    orderedKeys = Object.keys(params)
      .filter(key => key !== 'vnp_SecureHash' && key !== 'vnp_SecureHashType' && params[key] !== '' && params[key] !== null)
      .sort();
  } else {
    // Tạo URL thanh toán: Sử dụng thứ tự cố định theo mẫu URL chuẩn
    orderedKeys = [
      'vnp_Amount',
      'vnp_Command',
      'vnp_CreateDate',
      'vnp_CurrCode',
      'vnp_IpAddr',
      'vnp_Locale',
      'vnp_OrderInfo',
      'vnp_OrderType',
      'vnp_ReturnUrl',
      'vnp_TmnCode',
      'vnp_TxnRef',
      'vnp_Version',
      'vnp_ExpireDate',
      'vnp_Bill_Mobile',
      'vnp_Bill_Email',
      'vnp_Bill_FirstName',
      'vnp_Bill_LastName',
      'vnp_Bill_Address',
      'vnp_Bill_City',
      'vnp_Bill_Country',
      'vnp_Bill_State',
      'vnp_Inv_Phone',
      'vnp_Inv_Email',
      'vnp_Inv_Customer',
      'vnp_Inv_Address',
      'vnp_Inv_Company',
      'vnp_Inv_Taxcode',
      'vnp_Inv_Type',
      'vnp_BankCode',
    ].filter(key => params[key] !== undefined && params[key] !== '' && params[key] !== null);
  }

  // Tạo chuỗi signData
  const signData = orderedKeys
    .map(key => `${key}=${encodeURIComponent(params[key]).replace(/%20/g, '+')}`)
    .join('&');

  console.log('signData:', signData); // Log để debug

  // Tạo chữ ký bằng HMAC-SHA512
  return crypto.createHmac('sha512', secretKey).update(signData).digest('hex');
}

// Endpoint tạo thanh toán
app.post('/api/payments', authMiddleware, async (req, res) => {
  const {
    order_id,
    method,
    amount,
    order_desc = `Thanh toan don hang ${order_id}`,
    order_type = 'billpayment',
    language = 'vn',
    bank_code = '',
    txtexpire = '',
    txt_billing_mobile = '',
    txt_billing_email = '',
    txt_billing_fullname = '',
    txt_inv_addr1 = '',
    txt_bill_city = '',
    txt_bill_country = '',
    txt_bill_state = '',
    txt_inv_mobile = '',
    txt_inv_email = '',
    txt_inv_customer = '',
    txt_inv_company = '',
    txt_inv_taxcode = '',
    cbo_inv_type = '',
  } = req.body;
  const user_id = req.user.id;

  // Kiểm tra đầu vào
  if (!order_id || !method || !amount) {
    return res.status(400).json({ error: 'order_id, method, and amount are required' });
  }
  if (amount <= 0) {
    return res.status(400).json({ error: 'Amount must be greater than 0' });
  }

  try {
    // Kiểm tra đơn hàng
    const [orders] = await db.query('SELECT * FROM orders WHERE id = ? AND user_id = ?', [order_id, user_id]);
    if (!orders[0]) {
      return res.status(404).json({ error: 'Order not found or not authorized' });
    }

    // Kiểm tra thanh toán trùng lặp
    const [existingPayments] = await db.query('SELECT * FROM payments WHERE order_id = ?', [order_id]);
    if (existingPayments.length > 0) {
      const payment = existingPayments[0];
      if (payment.status === 'completed') {
        return res.status(400).json({ error: 'Payment already completed for this order' });
      }
      // Xóa bản ghi pending hoặc failed để tạo thanh toán mới
      if (payment.status === 'pending' || payment.status === 'failed' || payment.status === 'cancelled') {
        await db.query('DELETE FROM payments WHERE order_id = ?', [order_id]);
      }
    }

    let status = 'pending';
    let transaction_id = null;
    let payment_url = null;

    if (method === 'cash') {
      status = 'pending';
    } else if (method === 'online') {
      // Tạo tham số VNPAY
      const date = new Date();
      const createDate = `${date.getFullYear()}${String(date.getMonth() + 1).padStart(2, '0')}${String(date.getDate()).padStart(2, '0')}${String(date.getHours()).padStart(2, '0')}${String(date.getMinutes()).padStart(2, '0')}${String(date.getSeconds()).padStart(2, '0')}`;

      // Xử lý fullname
      let vnp_Bill_FirstName = '';
      let vnp_Bill_LastName = '';
      if (txt_billing_fullname && txt_billing_fullname.trim() !== '') {
        const name = txt_billing_fullname.trim().split(' ');
        vnp_Bill_FirstName = name.shift();
        vnp_Bill_LastName = name.pop() || '';
      }

      // Tạo object tham số
      const vnpParams = {
        vnp_Amount: (amount * 100).toString(),
        vnp_Command: 'pay',
        vnp_CreateDate: createDate,
        vnp_CurrCode: 'VND',
        vnp_IpAddr: req.ip || '127.0.0.1',
        vnp_Locale: language,
        vnp_OrderInfo: order_desc,
        vnp_OrderType: order_type,
        vnp_ReturnUrl: process.env.VNPAY_RETURN_URL,
        vnp_TmnCode: process.env.VNPAY_TMN_CODE,
        vnp_TxnRef: `ORDER_${order_id}_${Date.now()}`,
        vnp_Version: '2.1.0',
        ...(txtexpire && { vnp_ExpireDate: txtexpire }),
        ...(txt_billing_mobile && { vnp_Bill_Mobile: txt_billing_mobile }),
        ...(txt_billing_email && { vnp_Bill_Email: txt_billing_email }),
        ...(vnp_Bill_FirstName && { vnp_Bill_FirstName }),
        ...(vnp_Bill_LastName && { vnp_Bill_LastName }),
        ...(txt_inv_addr1 && { vnp_Bill_Address: txt_inv_addr1 }),
        ...(txt_bill_city && { vnp_Bill_City: txt_bill_city }),
        ...(txt_bill_country && { vnp_Bill_Country: txt_bill_country }),
        ...(txt_bill_state && { vnp_Bill_State: txt_bill_state }),
        ...(txt_inv_mobile && { vnp_Inv_Phone: txt_inv_mobile }),
        ...(txt_inv_email && { vnp_Inv_Email: txt_inv_email }),
        ...(txt_inv_customer && { vnp_Inv_Customer: txt_inv_customer }),
        ...(txt_inv_addr1 && { vnp_Inv_Address: txt_inv_addr1 }),
        ...(txt_inv_company && { vnp_Inv_Company: txt_inv_company }),
        ...(txt_inv_taxcode && { vnp_Inv_Taxcode: txt_inv_taxcode }),
        ...(cbo_inv_type && { vnp_Inv_Type: cbo_inv_type }),
        ...(bank_code && { vnp_BankCode: bank_code }),
      };

      // Tạo chữ ký bảo mật
      vnpParams.vnp_SecureHash = createVnpaySignature(vnpParams, process.env.VNPAY_HASH_SECRET);

      // Tạo URL thanh toán
      const orderedKeys = [
        'vnp_Amount',
        'vnp_Command',
        'vnp_CreateDate',
        'vnp_CurrCode',
        'vnp_IpAddr',
        'vnp_Locale',
        'vnp_OrderInfo',
        'vnp_OrderType',
        'vnp_ReturnUrl',
        'vnp_TmnCode',
        'vnp_TxnRef',
        'vnp_Version',
        'vnp_ExpireDate',
        'vnp_Bill_Mobile',
        'vnp_Bill_Email',
        'vnp_Bill_FirstName',
        'vnp_Bill_LastName',
        'vnp_Bill_Address',
        'vnp_Bill_City',
        'vnp_Bill_Country',
        'vnp_Bill_State',
        'vnp_Inv_Phone',
        'vnp_Inv_Email',
        'vnp_Inv_Customer',
        'vnp_Inv_Address',
        'vnp_Inv_Company',
        'vnp_Inv_Taxcode',
        'vnp_Inv_Type',
        'vnp_BankCode',
        'vnp_SecureHash',
      ].filter(key => vnpParams[key] !== undefined && vnpParams[key] !== '' && vnpParams[key] !== null);

      const querystring = orderedKeys
        .map(key => `${key}=${encodeURIComponent(vnpParams[key]).replace(/%20/g, '+')}`)
        .join('&');
      payment_url = `${process.env.VNPAY_URL}?${querystring}`;
      transaction_id = vnpParams.vnp_TxnRef;
      status = 'pending';
    } else {
      return res.status(400).json({ error: 'Invalid payment method' });
    }

    // Lưu thanh toán vào database
    const [result] = await db.query(
      'INSERT INTO payments (order_id, method, amount, status, transaction_id, created_at) VALUES (?, ?, ?, ?, ?, NOW())',
      [order_id, method, amount, status, transaction_id]
    );

    // Cập nhật trạng thái đơn hàng cho thanh toán bằng tiền mặt
    if (method === 'cash') {
      await db.query('UPDATE orders SET status = ? WHERE id = ?', ['confirmed', order_id]);
    }

    // Tạo vé nếu chưa có
    const [tickets] = await db.query('SELECT * FROM tickets WHERE order_id = ?', [order_id]);
    if (tickets.length === 0) {
      const ticket_code = `TICKET_${order_id}_${Date.now()}`;
      await db.query(
        'INSERT INTO tickets (order_id, ticket_code, issued_at) VALUES (?, ?, NOW())',
        [order_id, ticket_code]
      );
    }

    // Trả về phản hồi
    res.json({
      payment_id: result.insertId,
      order_id,
      method,
      amount,
      status,
      transaction_id,
      payment_url,
    });

    // Log để debug
    console.log('payment_url:', payment_url);
  } catch (err) {
    console.error('Error in /api/payments:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Endpoint xử lý callback từ VNPAY
app.get('/api/vnpay/return', async (req, res) => {
  try {
    const vnpParams = { ...req.query };
    const secureHash = vnpParams.vnp_SecureHash;
    delete vnpParams.vnp_SecureHash;
    delete vnpParams.vnp_SecureHashType;

    // Tạo chữ ký để kiểm tra
    const calculatedHash = createVnpaySignature(vnpParams, process.env.VNPAY_HASH_SECRET, true);

    console.log('secureHash:', secureHash);
    console.log('calculatedHash:', calculatedHash);
    console.log('vnpParams:', vnpParams);

    if (secureHash !== calculatedHash) {
      console.error('Invalid signature:', { secureHash, calculatedHash, vnpParams });
      return res.status(400).json({ error: 'Invalid signature' });
    }

    const order_id = vnpParams.vnp_TxnRef.split('_')[1];
    const vnp_ResponseCode = vnpParams.vnp_ResponseCode;

    if (vnp_ResponseCode === '00') {
      // Thanh toán thành công
      await db.query('UPDATE payments SET status = ? WHERE order_id = ?', ['completed', order_id]);
      await db.query('UPDATE orders SET status = ? WHERE id = ?', ['completed', order_id]);
      return res.redirect('http://localhost:3001/orders?payment=success');
    } else {
      // Thanh toán thất bại hoặc bị hủy
      await db.query('UPDATE payments SET status = ? WHERE order_id = ?', ['cancelled', order_id]);
      return res.redirect('http://localhost:3001/orders?payment=cancelled');
    }
  } catch (err) {
    console.error('Error in /api/vnpay/return:', err);
    res.status(500).json({ error: 'Server error' });
  }
});
////////////////////////////// end VNPAY //////////////////////////////////////

// Endpoint lấy danh sách đơn hàng đã quét (User)
app.get('/api/scanned-orders', authMiddleware, async (req, res) => {
  try {
    const user_id = req.user.id;
    const [orders] = await db.query('SELECT * FROM orders WHERE user_id = ? AND status = ?', [user_id, 'scanned']);
    res.json(orders);
  } catch (err) {
    console.error('Error in /api/scanned-orders:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Endpoint lấy danh sách đơn hàng đã quét (Admin)
app.get('/api/admin/scanned-orders', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  try {
    const [orders] = await db.query('SELECT o.*, u.email FROM orders o JOIN users u ON o.user_id = u.id WHERE o.status = ?', ['scanned']);
    res.json(orders);
  } catch (err) {
    console.error('Error in /api/admin/scanned-orders:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Endpoint quét mã QR (Admin)
app.post('/api/admin/scan-qr', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  const { ticket_code } = req.body;

  if (!ticket_code) {
    return res.status(400).json({ error: 'Ticket code is required' });
  }

  try {
    const [tickets] = await db.query('SELECT t.*, o.status FROM tickets t JOIN orders o ON t.order_id = o.id WHERE t.ticket_code = ?', [ticket_code]);
    if (!tickets[0]) {
      return res.status(404).json({ error: 'Ticket not found' });
    }

    const ticket = tickets[0];
    const orderStatus = ticket.status;

    if (ticket.is_used || orderStatus === 'scanned') {
      return res.status(400).json({ message: 'Mã đã qua sử dụng. Vui lòng đặt đơn hàng mới.' });
    }

    if (orderStatus === 'pending') {
      return res.status(400).json({ message: 'Đơn hàng của bạn chưa được xác nhận.' });
    }

    if (orderStatus === 'confirmed') {
      return res.status(400).json({ message: 'Vui lòng thanh toán trước khi nhận đồ ăn.' });
    }

    if (orderStatus === 'completed') {
      await db.query('UPDATE orders SET status = ? WHERE id = ?', ['scanned', ticket.order_id]);
      await db.query('UPDATE tickets SET is_used = 1 WHERE id = ?', [ticket.id]);
      return res.json({ message: 'Xác nhận thành công, chúc quý khách ngon miệng!' });
    }

    return res.status(400).json({ error: 'Invalid order status' });
  } catch (err) {
    console.error('Error in /api/admin/scan-qr:', err);
    res.status(500).json({ error: 'Server error' });
  }
});


// Endpoint lấy thông tin vé
app.get('/api/tickets/:orderId', authMiddleware, async (req, res) => {
  try {
    const orderId = req.params.orderId;
    const user_id = req.user.id;
    const [tickets] = await db.query('SELECT * FROM tickets WHERE order_id = ?', [orderId]);
    if (!tickets[0]) {
      return res.status(404).json({ error: 'Ticket not found' });
    }
    const [orders] = await db.query('SELECT * FROM orders WHERE id = ? AND user_id = ?', [orderId, user_id]);
    if (!orders[0]) {
      return res.status(403).json({ error: 'Order not authorized' });
    }
    res.json(tickets[0]);
  } catch (err) {
    console.error('Error in /api/tickets:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Endpoint lấy thông tin thanh toán
app.get('/api/payments/:orderId', authMiddleware, async (req, res) => {
  try {
    const orderId = req.params.orderId;
    const user_id = req.user.id;
    const [orders] = await db.query('SELECT * FROM orders WHERE id = ? AND user_id = ?', [orderId, user_id]);
    if (!orders[0]) {
      return res.status(403).json({ error: 'Order not authorized' });
    }
    const [payments] = await db.query('SELECT * FROM payments WHERE order_id = ?', [orderId]);
    if (!payments[0]) {
      return res.status(404).json({ error: 'Payment not found' });
    }
    res.json(payments[0]);
  } catch (err) {
    console.error('Error in /api/payments:', err);
    res.status(500).json({ error: 'Server error' });
  }
}); 

// Endpoint hủy đơn hàng
app.delete('/api/orders/:orderId', authMiddleware, async (req, res) => {
  try {
    const orderId = req.params.orderId;
    const user_id = req.user.id;
    const [orders] = await db.query('SELECT * FROM orders WHERE id = ? AND user_id = ?', [orderId, user_id]);
    if (!orders[0]) {
      return res.status(404).json({ error: 'Order not found or not authorized' });
    }
    await db.query('UPDATE orders SET status = ? WHERE id = ?', ['cancelled', orderId]);
    res.json({ message: 'Order cancelled successfully' });
  } catch (err) {
    console.error('Error in /api/orders/:orderId:', err);
    res.status(500).json({ error: 'Server error' });
  }
});
// Khởi động server
const PORT = 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));