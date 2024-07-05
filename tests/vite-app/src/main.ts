import "./style.css";
import { JwtVerifier } from "aws-jwt-verify";

const inputjwt = document.querySelector<HTMLInputElement>("#jwt");
const inputissuer = document.querySelector<HTMLInputElement>("#issuer");
const inputaudience = document.querySelector<HTMLInputElement>("#audience");
const inputjwskuri = document.querySelector<HTMLInputElement>("#jwksuri");
const button = document.querySelector<HTMLButtonElement>("#verifyrsa");
const result = document.querySelector<HTMLSpanElement>("#result");
const prettyprint = document.querySelector<HTMLPreElement>("#prettyprint");

function setInnerHtml(el: HTMLElement, value: string) {
  el.innerHTML = value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

if (inputjwt) {
  inputjwt.onkeyup = () => {
    if (inputjwt && button) {
      button.disabled = inputjwt.value === "";
    }
    if (result) {
      setInnerHtml(result, "Unverified");
    }
  };
}

if (button) {
  button.onclick = async () => {
    if (inputjwt && inputissuer && inputjwskuri && inputaudience && result) {
      const verifier = JwtVerifier.create({
        issuer: inputissuer?.value,
        audience: inputaudience?.value === "" ? null : inputaudience.value,
        jwksUri: inputjwskuri?.value,
      });

      try {
        const payload = await verifier.verify(inputjwt.value);
        console.log("Token is valid. Payload:", payload);

        setInnerHtml(result, "Verified");

        if (prettyprint) {
          setInnerHtml(prettyprint, JSON.stringify(payload, null, 2));
        }
      } catch (ex) {
        console.log(ex);
        console.log("Token not valid!");

        setInnerHtml(result, (ex as Error).toString());
      }
    }
  };
}
