//Task
//https://docs.google.com/document/d/1HWWFMSUzjLnkNRC8hciWJ18mOqhfFSxKllVJC2K5x8o/edit

const fs = require('fs');
const crypto = require('crypto');
const argon2 = require('argon2');

const PasswordType = Object.freeze({
    Top: 'Top',
    Common: 'Common',
    Random: 'Random'
});

function getRandom (min, max) {return Math.floor(Math.random() * (max - min) + min)};
function getRandom (max) {return Math.floor(Math.random() * max)};
shuffle = array => array.sort(() => Math.random() - 0.5);

const TOP_PASSWORDS_PATH = './passwords/top100.dat';
const MILLION_PASSWORDS_PATH = './passwords/million.dat';
const PASSWORD_DISTRIBUTION = new Map([[PasswordType.Top, 0.09],
                                       [PasswordType.Common, 0.9],
                                       [PasswordType.Random, 0.01]
                                      ]);
//Generate array of password type distribution
const PASSWORD_DISTRIBUTION_ARRAY = shuffle(Array.from(PASSWORD_DISTRIBUTION).map(([type, percent]) => Array(Math.floor(percent * 1000)).fill(type)).flat(1));
const ALPHABET_LOWERCASE = [...Array(26).keys()].map(el => String.fromCodePoint('a'.charCodeAt(0) + el));
const ALPHABET_UPPERCASE = ALPHABET_LOWERCASE.map(el => el.toUpperCase());
const SPECIAL_SYMBOLS = ['!', '@', '#', '$', '%', '^', '&', '*',
                         '(', ')', '"', '-', '+', '=', '_']

const PASSWORDS_FILES = new Map([[PasswordType.Top, fs.readFileSync('./passwords/top100.dat', 'utf8').split(/\r\n|\n/g)],
                                [PasswordType.Common, fs.readFileSync('./passwords/million.dat', 'utf8').split(/\r\n|\n/g)]]);

const getRandomType = () => PASSWORD_DISTRIBUTION_ARRAY[Math.floor(Math.random() * PASSWORD_DISTRIBUTION_ARRAY.length)];

const getTopPassword = () =>{
    const passwords = PASSWORDS_FILES.get(PasswordType.Top);
    const passwordIndex = Math.floor(Math.random() * passwords.length);
    return passwords[passwordIndex];
}

const getCommonPassword = () =>{
    const passwords = PASSWORDS_FILES.get(PasswordType.Common);
    const passwordIndex = Math.floor(Math.random() * passwords.length);
    return passwords[passwordIndex];
}

const getRandomChar = () =>{
    const charType = getRandom(3);
    let generatorArray;
    if(charType === 0){
        //Lowercase letter
        generatorArray = ALPHABET_LOWERCASE;
    } else if(charType === 1){
        //Uppercase letter
        generatorArray = ALPHABET_UPPERCASE;
    } else {
        //Special symbol
        generatorArray = SPECIAL_SYMBOLS;
    }
    return generatorArray[getRandom(generatorArray.length)];
}

const getRandomPassword = () =>{
    const passwordLength = getRandom(15, 64);
    return [...Array(passwordLength)].map(getRandomChar).join('');

}

const generatePassword = () => {
    const type = getRandomType();
    if(type === PasswordType.Top){
        return getTopPassword();
    } else if(type === PasswordType.Common){
        return getCommonPassword();
    } else if(type === PasswordType.Random){
        return getRandomPassword();
    } else {
        throw new Error("No such type exists");
    }
}

const passwordBunch = bunchSize => [...Array(bunchSize)].map(generatePassword);

const main = async () => {
    const PASSWORDS_NUMBER = 1e3;
    const passwords = passwordBunch(PASSWORDS_NUMBER);
    // console.log("Generating password:");
    // console.log(passwordsString);
    let passwordStream = fs.createWriteStream('./passwordBunch.txt', {flags:'a'});
    for(password in passwords){
        passwordStream.write(password + '\n')
    }
    passwordStream.end();
    
    const MD5_PATH = './hash/md5.csv';
    const SHA512_PATH = './hash/sha512.csv';
    const ARGON_PATH = './hash/argon2.csv';


    //Cipher into md5
    console.log("Started md5");
    if(fs.existsSync(MD5_PATH)){
        fs.unlinkSync(MD5_PATH);
    }
    let stream = fs.createWriteStream(MD5_PATH, {flags:'a'});
    stream.write('');
    for(password of passwords){
        const hashed = crypto.createHash('md5').update(password).digest('hex');
        stream.write(hashed + '\n')
    }
    stream.end();
    console.log("Finished md5");

    //Cipher into sha512
    console.log("Started sha512");
    if(fs.existsSync(SHA512_PATH)){
        fs.unlinkSync(SHA512_PATH);
    }
    stream = fs.createWriteStream(SHA512_PATH, {flags:'a'});
    for(password of passwords){
        const hashed = crypto.createHash('sha512').update(password).digest('hex');
        stream.write(hashed + '\n')
    }
    stream.end();
    console.log("Finished sha512");

    //Cipher into Argon2
    console.log("Started Argon2");
    if(fs.existsSync(ARGON_PATH)){
        fs.unlinkSync(ARGON_PATH);
    }
    stream = fs.createWriteStream(ARGON_PATH, {flags:'a'});
    stream.write('');
    for(password of passwords){
        const hashed = await argon2.hash(password);
        stream.write(hashed + '\n')
    }
    stream.end();
    console.log("Finished Argon2");
}

if(require.main === module){
    main();
}