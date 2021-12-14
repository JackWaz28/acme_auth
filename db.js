const Sequelize = require('sequelize');
const jwt = require('jsonwebtoken')
const bcrypt = require("bcrypt")
const { STRING } = Sequelize;
const config = {
    logging: false
};

const tokenSecret = 'ahdfsyufgyusguyg';
const saltRounds = 10;

if (process.env.LOGGING) {
    delete config.logging;
}
const conn = new Sequelize(process.env.DATABASE_URL || 'postgres://localhost/acme_db', config);

const User = conn.define('user', {
    username: STRING,
    password: STRING
});

User.byToken = async (token) => {
    try {

        const verifiedToken = jwt.verify(token, tokenSecret)
        console.log('Verified Token: ', verifiedToken)

        const user = await User.findByPk(verifiedToken.userId);
        if (user) {
            return user;
        }

        const error = Error('bad credentials');
        error.status = 401;
        throw error;
    }
    catch (ex) {
        const error = Error('bad credentials');
        error.status = 401;
        throw error;
    }
};

User.authenticate = async ({ username, password }) => {

    const user = await User.findOne({
        where: {
            username
        }
    });

    const correctPW = await bcrypt.compare(password, user.password)

    if (correctPW) {
        // return user.id;
        //put JWT SIGN here
        const token = jwt.sign({ userId: user.id, username: user.username }, tokenSecret)
        console.log('Token: ', token)
        return token
    }
    const error = Error('bad credentials');
    error.status = 401;
    throw error;
};


const syncAndSeed = async () => {
    await conn.sync({ force: true });
    const credentials = [
        { username: 'lucy', password: 'lucy_pw' },
        { username: 'moe', password: 'moe_pw' },
        { username: 'larry', password: 'larry_pw' }
    ];
    User.beforeCreate(async function(user, options) {
        const hashedPW = await bcrypt.hash(user.password, saltRounds)
        user.password = hashedPW;
        return user
    })
    const [lucy, moe, larry] = await Promise.all(
        credentials.map(credential => User.create(credential))
    );
    return {
        users: {
            lucy,
            moe,
            larry
        }
    };
};

module.exports = {
    syncAndSeed,
    models: {
        User
    }
};
