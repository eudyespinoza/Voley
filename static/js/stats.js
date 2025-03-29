function addStat(stat) {
    fetch('/api/update_stat', {
        method: 'POST',
        body: JSON.stringify({ jugador_id: selectedPlayerId, stat }),
        headers: { 'Content-Type': 'application/json' }
    });
}
