(async () => {
    "use strict";

    for (const param of document.location.search.slice(1).split("&")) {
        const name = param.split("=")[0];
        if (name === "file") {
            const serverName = param.split("=")[1];
            console.log(serverName);

            const file = await (await fetch("/api/file?file=" + serverName)).json();
            console.log(file);
            const eContent = document.getElementById("content");
            eContent.innerText = file.content;
        }
    }
})();