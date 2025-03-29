document.addEventListener("DOMContentLoaded", function () {
    const canvas = document.getElementById("strategyCanvas");
    const ctx = canvas.getContext("2d");

    function resizeCanvas() {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    }
    resizeCanvas();
    window.addEventListener("resize", resizeCanvas);

    let drawing = false;
    let paths = [];
    let redoStack = [];
    let currentPath = [];
    let drawMode = "line";
    let startX, startY;

    let colorPicker = document.getElementById("colorPicker");
    let lineWidth = document.getElementById("lineWidth");
    ctx.strokeStyle = colorPicker.value;
    ctx.lineWidth = lineWidth.value;

    function startDrawing(event) {
        drawing = true;
        currentPath = [];
        startX = event.clientX;
        startY = event.clientY;
        if (drawMode === "line") {
            ctx.beginPath();
            ctx.moveTo(startX, startY);
            currentPath.push({ x: startX, y: startY });
        }
    }

    function draw(event) {
        if (!drawing) return;

        if (drawMode === "line") {
            ctx.lineTo(event.clientX, event.clientY);
            ctx.stroke();
            currentPath.push({ x: event.clientX, y: event.clientY });
        } else if (drawMode === "circle") {
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            redraw();
            let radius = Math.sqrt(Math.pow(event.clientX - startX, 2) + Math.pow(event.clientY - startY, 2));
            ctx.beginPath();
            ctx.arc(startX, startY, radius, 0, 2 * Math.PI);
            ctx.stroke();
        }
    }

    function stopDrawing(event) {
        if (drawing) {
            if (drawMode === "circle") {
                let radius = Math.sqrt(Math.pow(event.clientX - startX, 2) + Math.pow(event.clientY - startY, 2));
                currentPath = { type: "circle", x: startX, y: startY, radius: radius };
            }
            paths.push(currentPath);
            redoStack = [];
        }
        drawing = false;
        redraw();
    }

    canvas.addEventListener("mousedown", startDrawing);
    canvas.addEventListener("mousemove", draw);
    canvas.addEventListener("mouseup", stopDrawing);
    canvas.addEventListener("mouseleave", stopDrawing);

    document.getElementById("clearCanvas").addEventListener("click", function () {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        paths = [];
        redoStack = [];
    });

    document.getElementById("undo").addEventListener("click", function () {
        if (paths.length > 0) {
            redoStack.push(paths.pop());
            redraw();
        }
    });

    document.getElementById("redo").addEventListener("click", function () {
        if (redoStack.length > 0) {
            paths.push(redoStack.pop());
            redraw();
        }
    });

    function redraw() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        for (let path of paths) {
            ctx.beginPath();
            if (path.type === "circle") {
                ctx.arc(path.x, path.y, path.radius, 0, 2 * Math.PI);
            } else {
                ctx.moveTo(path[0].x, path[0].y);
                for (let point of path) {
                    ctx.lineTo(point.x, point.y);
                }
            }
            ctx.stroke();
        }
    }

    colorPicker.addEventListener("input", function () {
        ctx.strokeStyle = colorPicker.value;
    });

    lineWidth.addEventListener("input", function () {
        ctx.lineWidth = lineWidth.value;
    });

    document.getElementById("modeLine").addEventListener("click", function () {
        drawMode = "line";
    });

    document.getElementById("modeCircle").addEventListener("click", function () {
        drawMode = "circle";
    });

    document.addEventListener("click", function (event) {
        const sidebar = document.getElementById("sidebar");
        const toggleSidebar = document.getElementById("toggleSidebar");
        if (!sidebar.contains(event.target) && !toggleSidebar.contains(event.target)) {
            sidebar.classList.remove("show");
        }
    });

    document.getElementById("toggleSidebar").addEventListener("click", function () {
        document.getElementById("sidebar").classList.toggle("show");
    });

    document.getElementById("closeSidebar").addEventListener("click", function () {
        document.getElementById("sidebar").classList.remove("show");
    });
});