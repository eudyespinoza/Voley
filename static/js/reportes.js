function cargarEstadisticas() {
    let jugador_id = document.getElementById("selectJugador").value;
    let partido_id = document.getElementById("selectPartido").value;

    fetch(`/api/estadisticas?jugador_id=${jugador_id}&partido_id=${partido_id}`)
        .then(response => response.json())
        .then(data => {
            let tabla = document.getElementById("tablaEstadisticas");
            tabla.innerHTML = "";
            data.forEach(est => {
                tabla.innerHTML += `<tr>
                    <td>${est.jugador}</td>
                    <td>${est.partido}</td>
                    <td>${est.ataques_efectivos}</td>
                    <td>${est.bloqueos_exitosos}</td>
                    <td>${est.saques_ace}</td>
                    <td>${est.recepciones_perfectas}</td>
                </tr>`;
            });

            actualizarGrafico(data);
        });
}

function actualizarGrafico(datos) {
    let ctx = document.getElementById("graficoEstadisticas").getContext("2d");
    let nombres = datos.map(e => e.jugador);
    let ataques = datos.map(e => e.ataques_efectivos);

    new Chart(ctx, {
        type: "bar",
        data: {
            labels: nombres,
            datasets: [{ label: "Ataques Efectivos", data: ataques, backgroundColor: "blue" }]
        }
    });
}

function exportarExcel() {
    window.open("/reportes/exportar/excel");
}

function exportarPDF() {
    window.open("/reportes/exportar/pdf");
}
