import { userURL } from "../utils/env.js";
import { tost } from "./Toastify.js";

document.addEventListener("DOMContentLoaded", () => {
  const signupForm = document.querySelector(".signup-form");
  const tarole = document.getElementById("taRole");
  const semesterSelection = document.getElementById("semester");
  const emailField = document.getElementById("email");

  tarole.style.display = "none";

  emailField.addEventListener("input", () => {
    if (emailField.value.endsWith("@mitaoe.ac.in")) {
      semesterSelection.style.display = "none";
      tarole.style.display = "block";
    } else {
      semesterSelection.style.display = "block";
      tarole.style.display = "none";
    }
  });

  signupForm.addEventListener("submit", (e) => {
    e.preventDefault();

    const formData = new FormData(signupForm);
    const formDataObject = {};

    formData.forEach((value, key) => {
      formDataObject[key] = value;
    });

    // ✅ Automatically append '@mitaoe.ac.in' if missing
    if (!formDataObject.email.includes("@")) {
      formDataObject.email += "@mitaoe.ac.in";
    }

    // ✅ Ensure email is either MIT email or ends with '@mitaoe.ac.in'
    if (
      !formDataObject.email.endsWith("@mitaoe.ac.in") &&
      !formDataObject.email.endsWith("@mitaoe.ac.in")
    ) {
      tost("Email should be an MIT email or end with @mitaoe.ac.in", "error", 3000);
      return;
    }

    console.log("Final Email:", formDataObject.email);

    const apiUrl = `${userURL}/signup`;
    const signUpLoader = document.getElementById("signUpLoader");
    const signUpBtnTxt = document.getElementById("signUpBtnTxt");

    signUpLoader.style.display = "block";
    signUpBtnTxt.style.display = "none";

    fetch(apiUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(formDataObject),
    })
      .then((response) => {
        if (response.status === 402) {
          tost("Email or username is already taken", "error", 3000);
          throw new Error("Email already taken");
        }
        if (response.status === 401) {
          tost("It should be an MIT email or a Gmail account", "error", 3000);
          throw new Error("Unauthorized - Invalid email");
        }
        if (!response.ok) {
          throw new Error(`Error: ${response.statusText}`);
        }
        return response.json();
      })
      .then((data) => {
        tost(
          "Please verify your email! Check inbox and junk folders. It may take a few minutes.",
          "info",
          5000
        );
        localStorage.setItem("userEmail", formDataObject.email);

        setTimeout(() => {
          window.location.href = "../html/verfiyEmail.html";
        }, 5000);
      })
      .catch((error) => {
        console.error("Fetch error:", error);
        signUpLoader.style.display = "none";
        signUpBtnTxt.style.display = "block";
      });
  });
});
