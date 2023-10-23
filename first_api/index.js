const http = require('http')
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt')
const { parse } = require('querystring');
require('dotenv').config()
const ratelimittime = 10*60*1000
const ratelimit = 5;
const iprequestlog = {}

const ipControl = (ip)=>{
    if (!iprequestlog[ip]) {
        iprequestlog[ip] = []
    }
    const now = Date.now()
    iprequestlog[ip] = iprequestlog[ip].filter(timestamp => now - timestamp < ratelimittime)
    if (iprequestlog[ip].length >= ratelimit) {
        return true
    }

    iprequestlog[ip].push(now)
    console.log(iprequestlog);
    return false

}


const PORT = 3000
mongoose.connect(process.env.MONGO_URL_PRODUCTS, { useNewUrlParser: true, useUnifiedTopology: true })
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB bağlantı hatası:'));
db.once('open', () => {
    console.log('product-MongoDB bağlantısı başarıyla kuruldu.');
});
const userdbconnect = mongoose.createConnection(process.env.MONGO_URL_USERS, { useNewUrlParser: true, useUnifiedTopology: true })
userdbconnect.on('error', console.error.bind(console, 'MongoDB bağlantı hatası:'));
userdbconnect.once('open', () => {
    console.log('user-MongoDB bağlantısı başarıyla kuruldu.');
});
const secretKey = process.env.JWT_SECRET_KEY; 
const generateToken = (userId) => {
    return jwt.sign({ userId }, secretKey, { expiresIn: '1h' });
};
const productSchema = new mongoose.Schema({
    name: String,
    price: Number
});
const userSchema = new mongoose.Schema({
    user: String,
    password: String,
    role: {
        type: String,
        enum: ['Admin', 'User'],
        default: 'User'
    }
})
const Product = mongoose.model('electronics', productSchema);
const User = userdbconnect.model('users', userSchema)
// const products = [
//     { id: 1, name: 'Apple Watch', price: 10000 },
//     { id: 2, name: 'Iphone 15', price: 25000 },
//     { id: 3, name: 'Apple Tv', price: 5000 }
// ]

const server = http.createServer(async (req, res) => {
    const clientip = req.socket.remoteAddress
    if (req.url === '/api/signup' && req.method === 'POST') {
        
        let body = ''
        req.on('data', (chunk) => {
            body += chunk.toString()
        })
        req.on('end', async () => {
            try{
            const { username, password, role } = JSON.parse(body)
        }catch(error){
            res.writeHead(400, { 'Content-type': 'application/json' });
            res.end(JSON.stringify({ error: 'Invalid JSON format' }));
            return;
        }
            if (!username || username.trim() === '') {
                res.writeHead(400, { 'Content-type': 'application/json' });
                res.end(JSON.stringify({ message: 'Username is required' }));
                return;
            }
            
            if (!password || password.trim() === '') {
                res.writeHead(400, { 'Content-type': 'application/json' });
                res.end(JSON.stringify({ message: 'Password is required' }));
                return;
            }
            const validusers = ['Admin','User']
            if (!role || role.trim() === ''|| !(validusers.includes(role))) {
                res.writeHead(400, { 'Content-type': 'application/json' });
                res.end(JSON.stringify({ message: 'Role is required and value is admin or user' }));
                return;
            }
            const existuser = await User.findOne({ username: username })

            if (existuser) {
                res.writeHead(400, { 'Content-type': 'application/json' })
                res.end(JSON.stringify({ message: 'user is exist' }))
                return}
            

            const saltround = 10
            const hashedpassword = await bcrypt.hash(password, saltround)
            const newuser = new User({
                user: username,
                password: hashedpassword,
                role: role

            })
            await newuser.save()

            res.writeHead(201, { 'Content-type': 'application/json' })
            res.end(JSON.stringify({ message: 'user sucessfully created' }))

        })

    } else if (req.url === '/api/login' && req.method === 'POST') {
        
        let body = ''
        req.on('data', (chunk) => {
            body += chunk.toString()
        })
        req.on('end', async () => {
            
                const { username, password } = JSON.parse(body)

            
            const user = await User.findOne({ user: username })
            if (!user) {
                res.writeHead(401, { 'Content-type': 'application/json' })
                res.end(JSON.stringify({ message: 'the user not found' }))
                return
            }
            const checkpassword = await bcrypt.compare(password, user.password)
            if (checkpassword) {
                const token = generateToken(user.id, user.role)
                res.writeHead(200, { 'Content-type': 'application/json' })
                res.end(JSON.stringify({ token }))
            } else {
                res.writeHead(401, { 'Content-type': 'application/json' })
                res.end(JSON.stringify({ message: 'wrong info' }))
            }
        })
    
    }else if(ipControl(clientip)){
        const firstrequest = iprequestlog[clientip][0]
        const currenthour = Date.now()
        const remaining = ratelimittime - (currenthour-firstrequest)
        res.writeHead(429,{'Content-type':'application/json'})
        res.end(JSON.stringify({message:`Too many request you have to wait ${(remaining/60000).toFixed(0)} minutes`}))
        return
    }
    else if (req.url.startsWith('/api/') && ['GET', 'POST', 'PUT', 'DELETE'].includes(req.method)) {
        const token = req.headers['authorization'];
        if (!token) {
            res.writeHead(401, { 'Content-Type': 'text/plain' });
            res.end('Token info is empty!');
            return;
        }
        jwt.verify(token, secretKey, async (err, decoded) => {
            if (err) {
                res.writeHead(403, { 'Content-Type': 'text/plain' });
                res.end('Token is expired!');
                return;
            }
            const user = await User.findById(decoded.userId)
            if (req.url === '/api/updateproduct' || req.url === '/api/deleteproduct' || req.url === '/api/addproduct' && user.role !== 'Admin') {
                res.writeHead(403, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ message: 'Access Denied' }));
                return;
            } else if (req.url === '/api/products' && req.method === 'GET') {
                const token = req.headers['authorization'];

                if (!token) {
                    res.writeHead(401, { 'Content-Type': 'text/plain' });
                    res.end('Token bulunamadi');
                    return;
                }
                jwt.verify(token, secretKey, (err, user) => {
                    if (err) {
                        res.writeHead(403, { 'Content-Type': 'text/plain' });
                        res.end('Yanlis Token');
                        return;
                    } else {
                        Product.find()
                            .then((products) => {
                                res.writeHead(200, { 'Content-Type': 'application/json' });
                                res.end(JSON.stringify(products));
                            })
                            .catch((err) => {
                                res.writeHead(500, { 'Content-Type': 'text/plain' });
                                res.end('Veritabanı hatası: ' + err.message);
                            });
                    }
                });
            } else if (req.url === '/api/addproduct' && req.method === 'POST') {
                const token = req.headers['authorization'];
                if (!token) {
                    res.writeHead(401, { 'Content-Type': 'text/plain' });
                    res.end('Token bulunamadi');
                    return;
                }
                jwt.verify(token, secretKey, (err, user) => {
                    if (err) {
                        res.writeHead(403, { 'Content-Type': 'text/plain' });
                        res.end('Yanlis Token');
                        return;
                    } else {
                        let body = ''
                        req.on('data', (chunk) => {
                            body += chunk.toString()
                        })
                        req.on('end', () => {
                            const parsedBody = JSON.parse(body)
                            if (!parsedBody.name || !parsedBody.price) {
                                res.writeHead(400, { 'Content-Type': 'text/plain' })
                                res.end('Urun ad veya fiyat eksik')
                                return
                            }
                            // const newProduct = {
                            //     id: generateUniqueId(),
                            //     name: parsedBody.name,
                            //     price: parseInt(parsedBody.price),
                            // }
                            const newProduct = new Product({
                                name: parsedBody.name,
                                price: parseInt(parsedBody.price),
                            })
                            newProduct.save()
                                .then(newproduct => {
                                    if (!newproduct) {
                                        res.writeHead('500', { 'Content-Type': 'text/plain' })
                                        res.end(newproduct)
                                    }
                                    res.writeHead('201', { 'Content-Type': 'application/json' })

                                    // const response = {
                                    //     status: 200,
                                    //     result: [newProduct]
                                    // }
                                    res.end(JSON.stringify(newproduct))
                                })


                        })
                    }
                })


            } else if (req.url === '/api/updateproduct' && req.method === 'POST') {
                const token = req.headers['authorization'];
                if (!token) {
                    res.writeHead(401, { 'Content-Type': 'text/plain' });
                    res.end('Token bulunamadi');
                    return;
                }
                jwt.verify(token, secretKey, (err, decoded) => {

                    if (err) {
                        res.writeHead(403, { 'Content-Type': 'text/plain' });
                        res.end('Yanlis Token');
                        return;
                    } else {
                        let body = '';
                        req.on('data', (chunk) => {
                            body += chunk.toString()
                        })
                        req.on('end', () => {
                            const parsedBody = JSON.parse(body)
                            const productID = parsedBody.id
                            Product.findByIdAndUpdate(productID, { name: parsedBody.name, price: parsedBody.price }, { new: true })
                                .then(updated => {
                                    res.writeHead(200, { 'Content-type': 'application/json' })
                                    res.end(JSON.stringify(updated))
                                })
                                .catch(error => {
                                    res.writeHead(404, { 'Content-type': 'text/plain' })
                                    res.end(error.message)
                                })
                        })


                    }
                })


                // const productToUpdate = products.find(product => product.id === parseInt(productID))

                // if (!productToUpdate) {
                //     res.writeHead(404, { 'Content-Type': 'text/plain' })
                //     res.end('Belirtilen id ye ait urun bulunamadi')
                //     return;
                // }
                // if (parsedBody.hasOwnProperty('name')) {
                //     productToUpdate.name = parsedBody.name
                // }
                // if (parsedBody.hasOwnProperty('price')) {
                //     productToUpdate.price = parsedBody.price
                // }



            } else if (req.url === '/api/deleteproduct' && req.method === 'DELETE') {
                const token = req.headers['authorization'];
                if (!token) {
                    res.writeHead(401, { 'Content-Type': 'text/plain' });
                    res.end('Token bulunamadi');
                    return;
                }
                jwt.verify(token, secretKey, (err, user) => {
                    if (err) {
                        res.writeHead(403, { 'Content-Type': 'text/plain' });
                        res.end('Yanlis Token');
                        return;
                    } else {
                        let body = '';

                        req.on('data', (chunk) => {
                            body += chunk.toString();
                        });

                        req.on('end', () => {
                            const parsedBody = JSON.parse(body);
                            const deletedProductId = parsedBody.id;

                            Product.deleteOne({ _id: deletedProductId })
                                .then(() => {
                                    res.writeHead(200, { 'Content-Type': 'application/json' });
                                    res.end(JSON.stringify({ status: 200, message: 'Product deleted successfully' }));
                                })
                                .catch(err => {
                                    res.writeHead(500, { 'Content-Type': 'application/json' });
                                    res.end(JSON.stringify({ status: 500, error: err.message }));
                                });
                        });
                    }
                })

            }
        })



    }

    else {
        res.writeHead(404, { 'Content-Type': 'text/plain' })
        res.end('Gecersiz endpoint')
    }

})

server.listen(PORT,'0.0.0.0', () => {
    console.log('API CALISIYOR');
})