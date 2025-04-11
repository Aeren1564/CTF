let args;
if (typeof process !== 'undefined') {
    const { argv } = require('process');
    args = argv.slice(2);
} else {
    args = arguments;
}

const N = parseInt(args[0]);
for (let i = 0; i < 112; i++) {
    console.log(Math.floor(Math.random()*N));
}
