(async () => {
    const me = await (await fetch("/api/me")).json();
    console.log(me);
})();