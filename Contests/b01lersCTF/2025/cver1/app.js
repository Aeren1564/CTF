const snarkjs = require("snarkjs");
const express = require("express");
const fs = require("fs");
const app = express();
const PORT = 20035;
module.exports = app;

const circname = "cverecord";

const vKey = JSON.parse(fs.readFileSync(`./${circname}_verification_key.json`));
const flag = fs.readFileSync(`./flag.txt`);

async function verifyProof(res, publicSignals, proof) {

	const verifies = await snarkjs.groth16.verify(vKey, publicSignals, proof);
	console.log(`Groth16Verify(\n\t${JSON.stringify(publicSignals)},\t\n${JSON.stringify(proof)}\n) === ${verifies}`);

	// TODO: check the correct value for out
	if (verifies === true) {
		console.log(publicSignals)
		if (parseInt(publicSignals[1]) <= 2025) {
				res.end("The most recent CVEs were published in 2025! This must be one of them.\n")
		}
		else {
			res.end("Wait, is your CVE from the future? Where did you find this???\n" + flag);
		}
	} else {
		res.end("Invalid proof!\n");
	}
}

app.use(express.json())
app.post('/', function (req, res) {
	Promise.resolve(verifyProof(res, req.body.input, req.body.proof));
});
