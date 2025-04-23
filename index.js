require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cloudinary = require('cloudinary').v2;

const app = express();

// Cho phép CORS từ web (React)
app.use(cors({
  origin: ['http://localhost:3000', 'http://localhost:3001', 'https://fastorder.vercel.app']
}));
app.use(express.json());

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
    return res.status(400).json({ error: 'Items are required and must be a non-empty array' });
  }

  try {
    // Tính tổng giá
    let total_price = 0;
    for (const item of items) {
      const { food_id, quantity } = item;
      if (!food_id || !quantity || quantity <= 0) {
        return res.status(400).json({ error: 'Each item must have food_id and quantity > 0' });
      }

      const [foods] = await db.query('SELECT price FROM food WHERE id = ?', [food_id]);
      if (!foods[0]) {
        return res.status(400).json({ error: `Food ${food_id} not found` });
      }
      total_price += foods[0].price * quantity;
    }

    // Tạo đơn hàng
    const [order] = await db.query(
      'INSERT INTO orders (user_id, total_price, status, created_at) VALUES (?, ?, ?, NOW())',
      [user_id, total_price, 'pending']
    );

    // Tạo các mục trong đơn hàng (order_items)
    for (const item of items) {
      const [foods] = await db.query('SELECT price FROM food WHERE id = ?', [item.food_id]);
      await db.query(
        'INSERT INTO order_items (order_id, food_id, quantity, unit_price) VALUES (?, ?, ?, ?)',
        [order.insertId, item.food_id, item.quantity, foods[0].price]
      );
    }

    // Tạo phiếu ăn (ticket)
    const ticket_code = require('crypto').randomBytes(8).toString('hex');
    await db.query(
      'INSERT INTO tickets (order_id, ticket_code, issued_at) VALUES (?, ?, NOW())',
      [order.insertId, ticket_code]
    );

    res.json({ order_id: order.insertId, total_price, status: 'pending', ticket_code });
  } catch (err) {
    console.error('Error in /orders (POST):', err);
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
app.post('/api/payments', authMiddleware, async (req, res) => {
  const { order_id, method, amount } = req.body;
  const user_id = req.user.id;

  if (!order_id || !method || !amount) {
    return res.status(400).json({ error: 'order_id, method, and amount are required' });
  }

  try {
    // Kiểm tra đơn hàng tồn tại và thuộc về người dùng
    const [orders] = await db.query('SELECT * FROM orders WHERE id = ? AND user_id = ?', [order_id, user_id]);
    if (!orders[0]) {
      return res.status(404).json({ error: 'Order not found or not authorized' });
    }

    // Tạo bản ghi thanh toán
    const transaction_id = method === 'cash' ? null : require('crypto').randomBytes(16).toString('hex');
    const [result] = await db.query(
      'INSERT INTO payments (order_id, amount, method, status, transaction_id, created_at) VALUES (?, ?, ?, ?, ?, NOW())',
      [order_id, amount, method, 'pending', transaction_id]
    );

    // Cập nhật trạng thái đơn hàng
    await db.query('UPDATE orders SET status = ? WHERE id = ?', ['confirmed', order_id]);

    res.json({
      payment_id: result.insertId,
      order_id,
      amount,
      method,
      status: 'pending',
      transaction_id
    });
  } catch (err) {
    console.error('Error in /payments (POST):', err);
    res.status(500).json({ error: 'Server error' });
  }
});

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

// Khởi động server
const PORT = 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));