fetch("/flag")
    .then(r => r.text())
    .then(t => {
        const d = document.createElement("div");
        d.setAttribute("flag", t);
        document.body.appendChild(d);
    });