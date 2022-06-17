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
    const passwords = passwordBunch(10e3);
    const passwordsString = passwords.join('\n');
    // console.log("Generating password:");
    // console.log(passwordsString);
    fs.writeFileSync('./passwordBunch.txt', passwordsString, {encoding: 'utf8'});

    //Cipher into md5
    fs.writeFileSync('./hash/md5.csv', passwords.map(a => crypto.createHash('md5').update(a).digest('hex')).join('\n') , {encoding: 'utf8'});

    //Cipher into sha256
    fs.writeFileSync('./hash/sha256.csv', passwords.map(a => crypto.createHash('sha256').update(a).digest('hex')).join('\n') , {encoding: 'utf8'});

    //Cipher into Argon2i
    fs.writeFileSync('./hash/argon2.csv', (await Promise.all(passwords.map(async a => await argon2.hash(a)))).join('\n') , {encoding: 'utf8'});
}

if(require.main === module){
    main();
}