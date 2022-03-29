import "./style.css";
import { JwtRsaVerifier } from "aws-jwt-verify";

const inputjwt = document.querySelector<HTMLInputElement>("#jwt");
const inputissuer = document.querySelector<HTMLInputElement>("#issuer");
const inputaudience = document.querySelector<HTMLInputElement>("#audience");
const inputjwskuri = document.querySelector<HTMLInputElement>("#jwksuri");
const button = document.querySelector<HTMLButtonElement>("#verifyrsa");
const result = document.querySelector<HTMLSpanElement>("#result");
const prettyprint = document.querySelector<HTMLPreElement>("#prettyprint");

if (inputjwt) {
  inputjwt.onkeyup = () => {
    if (inputjwt && button) {
      button.disabled = inputjwt.value === "";
    }
    if (result) {
      result.innerHTML = "Unverified";
    }
  };
}

if (button) {
  button.onclick = async () => {
    if (inputjwt && inputissuer && inputjwskuri && inputaudience && result) {
      const verifier = JwtRsaVerifier.create({
        issuer: inputissuer?.value,
        audience: inputaudience?.value === "" ? null : inputaudience.value,
        jwksUri: inputjwskuri?.value,
      });

      try {
        const payload = await verifier.verify(inputjwt.value);
        console.log("Token is valid. Payload:", payload);

        result.innerHTML = "Verified";

        if (prettyprint) {
          prettyprint.innerHTML = JSON.stringify(payload, null, 2);
        }
      } catch (ex) {
        console.log(ex);
        console.log("Token not valid!");

        result.innerHTML = (ex as Error).message;
      }
    }
  };
}
