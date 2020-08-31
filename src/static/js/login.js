(async () => {
    "use strict";

    const loginButton = document.getElementById("loginButton");
    loginButton.addEventListener("click", async (ev) => {
        const username = document.getElementById("username").value;
        const password = document.getElementById("password").value;

        const res = await (await fetch("/api/login", {
            "method": "POST",
            "body": JSON.stringify({
                "username": username,
                "password": password,
            })
        })).json();
        if (res.success || !res.error) {
            // Logged in successfully, sessionToken should be set automatically so can redirect to /
            document.location = "/";
        }
        console.log(res);
    });
})();