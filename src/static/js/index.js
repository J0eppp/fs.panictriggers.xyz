(async () => {
    "use strict";
    const me = await (await fetch("/api/me")).json();
    console.log(me);

    const files = await (await fetch("/api/files")).json();

    console.log(files);

    const eFiles = document.getElementById("files");

    files.forEach(file => {
        const a = document.createElement("a");
        a.href = "/file?file=" + file.serverName;
        if (file.public) {
            a.innerText = file.filename + " [PUBLIC]";
        } else {
            a.innerText = file.filename;
        }
        // a.innerText = file.filename + (file.public === true) ? " [PUBLIC]" : "";
        eFiles.appendChild(a);
    });
})();