const jwt = require("jsonwebtoken");
const secret = process.env.ACCESS_TOKEN_SECRET;
const refreshSecret = process.env.REFRESH_TOKEN_SECRET;

function getEntriesFromCookie(req, res) {
  let authCookie = "";
  let refreshToken = "";

  if (req.headers.cookie) {
    if (req.headers.cookie.includes("authcookie")) {
      authCookie = req.headers.cookie?.split("authcookie=")[1]?.split(";")[0] || "";
    }
    if (req.headers.cookie.includes("refreshToken")) {
      refreshToken = req.headers.cookie?.split("refreshToken=")[1]?.split(";")[0] || "";
    }
  }

  if (!authCookie && !refreshToken) {
    console.error("No tokens found in cookies");
    return null;
  }

  try {
    // Verify the access token
    const decodedAccessToken = jwt.verify(authCookie, secret);
    return decodedAccessToken;
  } catch (accessError) {
    console.error("Access token error:", accessError.message);

    // Try using refresh token if access token fails
    try {
      const decodedRefreshToken = jwt.verify(refreshToken, refreshSecret);
      const { email, isAdmin } = decodedRefreshToken;
      
      // Generate a new access token
      const newAccessToken = jwt.sign({ email, isAdmin }, secret, { expiresIn: "2h" });
      const newDecodedToken = jwt.verify(newAccessToken, secret);

      // Set new access token in cookie (if response object available)
      if (res) {
        res.cookie("authcookie", newAccessToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: "Strict",
        });
      }

      return newDecodedToken;
    } catch (refreshError) {
      console.error("Refresh token verification error:", refreshError.message);
      return null;
    }
  }
}

exports.getEntriesFromCookie = getEntriesFromCookie;
