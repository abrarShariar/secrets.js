const utility = require('./secret_utility');
let text = ""

text = "Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
const secret_generator = new utility.SecretGenerator(text);
const secrets = secret_generator.run();
console.log(secrets);

const secret_recoverer = new utility.SecretRecoverer(secrets);
const result = secret_recoverer.run();

console.log(String(result) === String(text));
