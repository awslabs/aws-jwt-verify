import { CognitoJwtVerifier } from "aws-jwt-verify";
import { assertStringEquals } from "aws-jwt-verify/assert";

const jwtVerifier = CognitoJwtVerifier.create({
  userPoolId: process.env.USER_POOL_ID,
  tokenUse: "id",
  clientId: process.env.CLIENT_ID,
  customJwtCheck: ({ payload }) => {
    assertStringEquals("e-mail", payload["email"], process.env.USER_EMAIL);
  },
});

await jwtVerifier.hydrate();

export const handler = async (event) => {
  console.log("request:", JSON.stringify(event, undefined, 2));

  const jwt = event.headers.authorization;
  try {
    const payload = await jwtVerifier.verify(jwt);
    console.log("Access allowed. JWT payload:", payload);
  } catch (err) {
    console.error("Access forbidden:", err);
    return {
      isAuthorized: false,
    };
  }
  return {
    isAuthorized: true,
  };
};
