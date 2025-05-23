import os
import matplotlib.pyplot as plt
from io import BytesIO
import re
import base64
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import date
import bcrypt
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, Image
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
import time
from queue import Queue
import threading
import json

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///volley_stats.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'ounewf7efnwo8ghwoe8gh'

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Cola de eventos para SSE
event_queues = {}  # Diccionario para almacenar colas por sesión de cliente
event_lock = threading.Lock()

os.makedirs('static/reports', exist_ok=True)

# Modelo de Usuario
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    email = db.Column(db.String(120), unique=True, nullable=True)

    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Modelos existentes
equipo_jugador = db.Table(
    'equipo_jugador',
    db.Column('equipo_id', db.Integer, db.ForeignKey('equipos.id'), primary_key=True),
    db.Column('jugador_id', db.Integer, db.ForeignKey('jugadores.id'), primary_key=True)
)

class Equipo(db.Model):
    __tablename__ = 'equipos'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False, unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    jugadores = db.relationship("Jugador", secondary=equipo_jugador, backref="equipos")

    def __init__(self, nombre, user_id):
        self.nombre = nombre
        self.user_id = user_id

class Jugador(db.Model):
    __tablename__ = 'jugadores'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    numero = db.Column(db.Integer, nullable=False, unique=True)
    posicion = db.Column(db.String(50), nullable=False)
    altura = db.Column(db.Float, nullable=True)
    peso = db.Column(db.Float, nullable=True)
    mano_dominante = db.Column(db.String(10), nullable=True)
    grupo_sanguineo = db.Column(db.String(10), nullable=True)
    historial_lesiones = db.Column(db.Text, nullable=True)
    ataques_efectivos = db.Column(db.Integer, default=0)
    ataques_fallidos = db.Column(db.Integer, default=0)
    bloqueos_exitosos = db.Column(db.Integer, default=0)
    bloqueos_fallidos = db.Column(db.Integer, default=0)
    saques_ace = db.Column(db.Integer, default=0)
    saques_fallidos = db.Column(db.Integer, default=0)
    recepciones_perfectas = db.Column(db.Integer, default=0)
    recepciones_fallidas = db.Column(db.Integer, default=0)
    asistencias = db.Column(db.Integer, default=0)
    errores_no_forzados = db.Column(db.Integer, default=0)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    partidos = db.relationship('EstadisticaPartido', back_populates='jugador')

    def __init__(self, nombre, numero, posicion, equipo_id, user_id, altura=None, peso=None, mano_dominante=None,
                 grupo_sanguineo=None, historial_lesiones=None):
        self.nombre = nombre
        self.numero = numero
        self.posicion = posicion
        self.user_id = user_id
        equipo = db.session.get(Equipo, equipo_id)
        if equipo:
            self.equipos.append(equipo)

class Partido(db.Model):
    __tablename__ = 'partidos'
    id = db.Column(db.Integer, primary_key=True)
    fecha = db.Column(db.Date, default=date.today, nullable=False)
    rival = db.Column(db.String(100), nullable=False)
    equipo_id = db.Column(db.Integer, db.ForeignKey('equipos.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    equipo = db.relationship('Equipo', backref=db.backref('partidos', lazy=True))
    titulares = db.Column(db.JSON, nullable=False, default=[])
    estado = db.Column(db.String(20), default="En curso")
    marcador_local = db.Column(db.Integer, default=0)
    marcador_visitante = db.Column(db.Integer, default=0)
    set_scores = db.Column(db.JSON, nullable=False, default=[])
    es_local = db.Column(db.Boolean, default=True)
    tipo_partido = db.Column(db.String(20), default="Amistoso")
    estadisticas = db.relationship('EstadisticaPartido', back_populates='partido')

    def __init__(self, rival, equipo_id, user_id, es_local=True, tipo_partido="Amistoso"):
        self.rival = rival
        self.equipo_id = equipo_id
        self.user_id = user_id
        self.titulares = []
        self.estado = "En curso"
        self.set_scores = []
        self.es_local = es_local
        self.tipo_partido = tipo_partido

class EstadisticaPartido(db.Model):
    __tablename__ = 'estadisticas_partido'
    id = db.Column(db.Integer, primary_key=True)
    partido_id = db.Column(db.Integer, db.ForeignKey('partidos.id'), nullable=False)
    jugador_id = db.Column(db.Integer, db.ForeignKey('jugadores.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    jugador = db.relationship('Jugador', back_populates='partidos')
    partido = db.relationship('Partido', back_populates='estadisticas')
    saques_ace = db.Column(db.Integer, default=0)
    saques_fallidos = db.Column(db.Integer, default=0)
    saques_totales = db.Column(db.Integer, default=0)
    ataques_puntos = db.Column(db.Integer, default=0)
    ataques_fallidos = db.Column(db.Integer, default=0)
    ataques_bloqueados = db.Column(db.Integer, default=0)
    ataques_totales = db.Column(db.Integer, default=0)
    recepciones_perfectas = db.Column(db.Integer, default=0)
    recepciones_positivas = db.Column(db.Integer, default=0)
    recepciones_fallidas = db.Column(db.Integer, default=0)
    bloqueos_puntos = db.Column(db.Integer, default=0)
    bloqueos_toques = db.Column(db.Integer, default=0)
    defensas_levantadas = db.Column(db.Integer, default=0)
    defensas_fallidas = db.Column(db.Integer, default=0)
    asistencias = db.Column(db.Integer, default=0)
    asistencias_fallidas = db.Column(db.Integer, default=0)
    posicion = db.Column(db.Integer, default=1)
    notas = db.Column(db.Text, nullable=True)

    def __init__(self, partido_id, jugador_id, user_id, posicion=1):
        self.partido_id = partido_id
        self.jugador_id = jugador_id
        self.user_id = user_id
        self.posicion = posicion

# Rutas de Autenticación
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('home'))
        flash('Usuario o contraseña incorrectos')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Rutas de Administración
@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
def admin_users():
    if not current_user.is_admin:
        return "Acceso denegado", 403
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'create':
            username = request.form['username']
            password = request.form['password']
            email = request.form.get('email')
            if User.query.filter_by(username=username).first():
                flash('El usuario ya existe')
            else:
                user = User(username=username, email=email)
                user.set_password(password)
                db.session.add(user)
                db.session.commit()
                flash('Usuario creado exitosamente')
        elif action == 'edit':
            user_id = request.form['user_id']
            user = db.session.get(User, user_id)
            if user:
                user.username = request.form['username']
                user.email = request.form.get('email')
                if request.form['password']:
                    user.set_password(request.form['password'])
                db.session.commit()
                flash('Usuario actualizado')
        elif action == 'delete':
            user_id = request.form['user_id']
            user = db.session.get(User, user_id)
            if user and not user.is_admin:
                db.session.delete(user)
                db.session.commit()
                flash('Usuario eliminado')
    users = User.query.all()
    return render_template('admin_users.html', users=users)

# Rutas Existentes
@app.route('/')
@login_required
def home():
    return render_template('index.html')

@app.route('/equipos')
@login_required
def listar_equipos():
    if current_user.is_admin:
        equipos = Equipo.query.all()
    else:
        equipos = Equipo.query.filter_by(user_id=current_user.id).all()
    return render_template('equipos.html', equipos=equipos)

@app.route('/equipos/nuevo', methods=['POST'])
@login_required
def crear_equipo():
    nombre = request.form.get('nombre')
    nuevo_equipo = Equipo(nombre=nombre, user_id=current_user.id)
    db.session.add(nuevo_equipo)
    db.session.commit()
    return redirect(url_for('listar_equipos'))

@app.route('/equipos/editar/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_equipo(id):
    equipo = db.session.get(Equipo, id)
    if not equipo or (equipo.user_id != current_user.id and not current_user.is_admin):
        return "Equipo no encontrado o acceso denegado", 404
    if request.method == 'POST':
        equipo.nombre = request.form.get('nombre')
        db.session.commit()
        return redirect(url_for('listar_equipos'))
    return render_template('editar_equipo.html', equipo=equipo)

@app.route('/equipos/eliminar/<int:id>', methods=['POST'])
@login_required
def eliminar_equipo(id):
    equipo = db.session.get(Equipo, id)
    if equipo and (equipo.user_id == current_user.id or current_user.is_admin):
        db.session.delete(equipo)
        db.session.commit()
    return jsonify({'message': 'Equipo eliminado'})

@app.route('/jugadores')
@login_required
def listar_jugadores():
    if current_user.is_admin:
        jugadores = Jugador.query.all()
        equipos = Equipo.query.all()
    else:
        jugadores = Jugador.query.filter_by(user_id=current_user.id).all()
        equipos = Equipo.query.filter_by(user_id=current_user.id).all()
    return render_template('jugadores.html', jugadores=jugadores, equipos=equipos)

@app.route('/jugadores/nuevo', methods=['POST'])
@login_required
def crear_jugador():
    nombre = request.form.get('nombre')
    numero = request.form.get('numero')
    posicion = request.form.get('posicion')
    equipo_id = request.form.get('equipo')
    altura = request.form.get('altura', type=float)
    peso = request.form.get('peso', type=float)
    mano_dominante = request.form.get('mano_dominante')
    grupo_sanguineo = request.form.get('grupo_sanguineo')
    historial_lesiones = request.form.get('historial_lesiones')
    nuevo_jugador = Jugador(
        nombre=nombre, numero=numero, posicion=posicion, equipo_id=equipo_id,
        user_id=current_user.id, altura=altura, peso=peso, mano_dominante=mano_dominante,
        grupo_sanguineo=grupo_sanguineo, historial_lesiones=historial_lesiones
    )
    db.session.add(nuevo_jugador)
    db.session.commit()
    return redirect(url_for('listar_jugadores'))

@app.route('/jugadores/editar/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_jugador(id):
    jugador = db.session.get(Jugador, id)
    if not jugador or (jugador.user_id != current_user.id and not current_user.is_admin):
        return "Jugador no encontrado o acceso denegado", 404
    equipos = Equipo.query.filter_by(user_id=current_user.id).all() if not current_user.is_admin else Equipo.query.all()
    if request.method == 'POST':
        jugador.nombre = request.form.get('nombre')
        jugador.numero = request.form.get('numero')
        jugador.posicion = request.form.get('posicion')
        equipo_id = request.form.get('equipo')
        jugador.altura = request.form.get('altura', type=float)
        jugador.peso = request.form.get('peso', type=float)
        jugador.mano_dominante = request.form.get('mano_dominante')
        jugador.grupo_sanguineo = request.form.get('grupo_sanguineo')
        jugador.historial_lesiones = request.form.get('historial_lesiones')
        equipo = db.session.get(Equipo, equipo_id)
        if equipo:
            if jugador.equipos:
                jugador.equipos[0] = equipo
            else:
                jugador.equipos.append(equipo)
        db.session.commit()
        return redirect(url_for('listar_jugadores'))
    return render_template('editar_jugador.html', jugador=jugador, equipos=equipos)

@app.route('/jugadores/eliminar/<int:id>', methods=['POST'])
@login_required
def eliminar_jugador(id):
    jugador = db.session.get(Jugador, id)
    if jugador and (jugador.user_id == current_user.id or current_user.is_admin):
        db.session.delete(jugador)
        db.session.commit()
    return jsonify({'message': 'Jugador eliminado'})

@app.route('/partido')
@login_required
def listar_partidos():
    if current_user.is_admin:
        partidos = Partido.query.order_by(Partido.fecha.desc()).all()
        equipos = Equipo.query.all()
        jugadores = Jugador.query.all()
    else:
        partidos = Partido.query.filter_by(user_id=current_user.id).order_by(Partido.fecha.desc()).all()
        equipos = Equipo.query.filter_by(user_id=current_user.id).all()
        jugadores = Jugador.query.filter_by(user_id=current_user.id).all()
    return render_template('partido.html', partidos=partidos, equipos=equipos, jugadores=jugadores)

@app.route('/partido/nuevo', methods=['POST'])
@login_required
def crear_partido():
    rival = request.form.get('rival')
    equipo_id = request.form.get('equipo')
    es_local = request.form.get('es_local') == 'local'
    tipo_partido = request.form.get('tipo_partido')
    nuevo_partido = Partido(rival=rival, equipo_id=equipo_id, user_id=current_user.id, es_local=es_local,
                            tipo_partido=tipo_partido)
    db.session.add(nuevo_partido)
    db.session.commit()
    return redirect(url_for('listar_partidos'))

@app.route('/partido/editar/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_partido(id):
    partido = db.session.get(Partido, id)
    if not partido or (partido.user_id != current_user.id and not current_user.is_admin):
        return "Partido no encontrado o acceso denegado", 404
    equipos = Equipo.query.filter_by(user_id=current_user.id).all() if not current_user.is_admin else Equipo.query.all()
    if request.method == 'POST':
        partido.rival = request.form.get('rival')
        partido.equipo_id = request.form.get('equipo')
        partido.es_local = request.form.get('es_local') == 'local'
        partido.tipo_partido = request.form.get('tipo_partido')
        db.session.commit()
        return redirect(url_for('listar_partidos'))
    return render_template('partido.html', partidos=Partido.query.order_by(Partido.fecha.desc()).all(), equipos=equipos)

@app.route('/partido/eliminar/<int:id>', methods=['POST'])
@login_required
def eliminar_partido(id):
    partido = db.session.get(Partido, id)
    if partido and (partido.user_id == current_user.id or current_user.is_admin):
        db.session.delete(partido)
        db.session.commit()
    return jsonify({'message': 'Partido eliminado'})

@app.route('/partido/estadisticas/<int:partido_id>')
@login_required
def estadisticas_partido(partido_id):
    partido = db.session.get(Partido, partido_id)
    if not partido or (partido.user_id != current_user.id and not current_user.is_admin):
        return "Partido no encontrado o acceso denegado", 404
    equipo = partido.equipo
    jugadores = equipo.jugadores
    jugadores_data = [{"id": j.id, "numero": j.numero, "nombre": j.nombre, "posicion": j.posicion} for j in jugadores]
    estadisticas = EstadisticaPartido.query.filter_by(partido_id=partido_id).all()
    return render_template('estadisticas_partido.html', partido=partido, estadisticas=estadisticas,
                           jugadores=jugadores_data)

@app.route('/partido/finalizar/<int:partido_id>', methods=['POST'])
@login_required
def finalizar_partido(partido_id):
    partido = db.session.get(Partido, partido_id)
    if not partido or (partido.user_id != current_user.id and not current_user.is_admin):
        return jsonify({'error': 'Partido no encontrado o acceso denegado'}), 404
    data = request.get_json()
    partido.estado = "Finalizado"
    partido.marcador_local = data.get('marcador_local', partido.marcador_local)
    partido.marcador_visitante = data.get('marcador_visitante', partido.marcador_visitante)
    partido.set_scores = data.get('set_scores', partido.set_scores)
    db.session.commit()
    return jsonify({'message': 'Partido finalizado correctamente'})

# Función para generar gráficos y devolverlos como base64
def generate_chart(data, labels, title, colors):
    plt.figure(figsize=(6, 4))
    plt.bar(labels, data, color=colors)
    plt.title(title)
    plt.xlabel('Categorías')
    plt.ylabel('Cantidad')
    plt.tight_layout()
    img = BytesIO()
    plt.savefig(img, format='png')
    img.seek(0)
    plt.close()
    return base64.b64encode(img.getvalue()).decode('utf-8')

# SSE event generator
def event_stream(session_id):
    with event_lock:
        if session_id not in event_queues:
            event_queues[session_id] = Queue()
    queue = event_queues[session_id]
    try:
        while True:
            message = queue.get()
            yield f"data: {json.dumps(message)}\n\n"
    except GeneratorExit:
        with event_lock:
            del event_queues[session_id]

# SSE endpoint
@app.route('/events/<session_id>')
@login_required
def sse_events(session_id):
    return Response(event_stream(session_id), mimetype='text/event-stream')

# Broadcast event to all connected clients
def broadcast_event(event_type, data):
    with event_lock:
        for queue in event_queues.values():
            queue.put({'event': event_type, 'data': data})

@app.route('/exportar_pdf', methods=['POST'])
@login_required
def exportar_pdf():
    tipo = request.form.get('tipo')
    jugador_id = request.form.get('jugador_id')
    partido_id = request.form.get('partido_id')
    equipo_id = request.form.get('equipo_id')

    print(f"Received request: tipo={tipo}, jugador_id={jugador_id}, partido_id={partido_id}, equipo_id={equipo_id}")

    # Fetch data based on type
    if tipo == 'por_partido' and jugador_id and partido_id:
        estadistica = EstadisticaPartido.query.filter_by(jugador_id=jugador_id, partido_id=partido_id).first()
        if not estadistica or (estadistica.user_id != current_user.id and not current_user.is_admin):
            print("Error: Estadísticas no encontradas o acceso denegado")
            return jsonify({"error": "Estadísticas no encontradas o acceso denegado"}), 404
        partido = db.session.get(Partido, partido_id)
        datos = {
            "jugador": estadistica.jugador.nombre,
            "partido": f"{partido.equipo.nombre} vs {partido.rival}",
            "saques_ace": estadistica.saques_ace,
            "saques_fallidos": estadistica.saques_fallidos,
            "saques_totales": estadistica.saques_totales,
            "ataques_puntos": estadistica.ataques_puntos,
            "ataques_fallidos": estadistica.ataques_fallidos,
            "ataques_bloqueados": estadistica.ataques_bloqueados,
            "ataques_totales": estadistica.ataques_totales,
            "efectividad_ataque": (
                estadistica.ataques_puntos / estadistica.ataques_totales * 100) if estadistica.ataques_totales > 0 else 0,
            "recepciones_perfectas": estadistica.recepciones_perfectas,
            "recepciones_positivas": estadistica.recepciones_positivas,
            "recepciones_fallidas": estadistica.recepciones_fallidas,
            "bloqueos_puntos": estadistica.bloqueos_puntos,
            "bloqueos_toques": estadistica.bloqueos_toques,
            "defensas_levantadas": estadistica.defensas_levantadas,
            "defensas_fallidas": estadistica.defensas_fallidas,
            "asistencias": estadistica.asistencias,
            "asistencias_fallidas": estadistica.asistencias_fallidas
        }
    elif tipo == 'generales' and jugador_id:
        estadisticas = EstadisticaPartido.query.filter_by(jugador_id=jugador_id).all()
        if not estadisticas or (estadisticas[0].user_id != current_user.id and not current_user.is_admin):
            print("Error: Estadísticas no encontradas o acceso denegado")
            return jsonify({"error": "Estadísticas no encontradas o acceso denegado"}), 404
        datos = {
            "jugador": estadisticas[0].jugador.nombre,
            "saques_ace": sum(e.saques_ace for e in estadisticas),
            "saques_fallidos": sum(e.saques_fallidos for e in estadisticas),
            "saques_totales": sum(e.saques_totales for e in estadisticas),
            "ataques_puntos": sum(e.ataques_puntos for e in estadisticas),
            "ataques_fallidos": sum(e.ataques_fallidos for e in estadisticas),
            "ataques_bloqueados": sum(e.ataques_bloqueados for e in estadisticas),
            "ataques_totales": sum(e.ataques_totales for e in estadisticas),
            "efectividad_ataque": (
                sum(e.ataques_puntos for e in estadisticas) / sum(e.ataques_totales for e in estadisticas) * 100
            ) if sum(e.ataques_totales for e in estadisticas) > 0 else 0,
            "recepciones_perfectas": sum(e.recepciones_perfectas for e in estadisticas),
            "recepciones_positivas": sum(e.recepciones_positivas for e in estadisticas),
            "recepciones_fallidas": sum(e.recepciones_fallidas for e in estadisticas),
            "bloqueos_puntos": sum(e.bloqueos_puntos for e in estadisticas),
            "bloqueos_toques": sum(e.bloqueos_toques for e in estadisticas),
            "defensas_levantadas": sum(e.defensas_levantadas for e in estadisticas),
            "defensas_fallidas": sum(e.defensas_fallidas for e in estadisticas),
            "asistencias": sum(e.asistencias for e in estadisticas),
            "asistencias_fallidas": sum(e.asistencias_fallidas for e in estadisticas)
        }
    elif tipo == 'equipo' and equipo_id:
        equipo = db.session.get(Equipo, equipo_id)
        if not equipo or (equipo.user_id != current_user.id and not current_user.is_admin):
            print("Error: Equipo no encontrado o acceso denegado")
            return jsonify({"error": "Equipo no encontrado o acceso denegado"}), 404
        jugadores = equipo.jugadores
        estadisticas = EstadisticaPartido.query.filter(
            EstadisticaPartido.jugador_id.in_([j.id for j in jugadores])).all()
        if not estadisticas:
            print("Error: Estadísticas no encontradas")
            return jsonify({"error": "Estadísticas no encontradas"}), 404
        datos = {
            "equipo": equipo.nombre,
            "saques_ace": sum(e.saques_ace for e in estadisticas),
            "saques_fallidos": sum(e.saques_fallidos for e in estadisticas),
            "saques_totales": sum(e.saques_totales for e in estadisticas),
            "ataques_puntos": sum(e.ataques_puntos for e in estadisticas),
            "ataques_fallidos": sum(e.ataques_fallidos for e in estadisticas),
            "ataques_bloqueados": sum(e.ataques_bloqueados for e in estadisticas),
            "ataques_totales": sum(e.ataques_totales for e in estadisticas),
            "efectividad_ataque": (
                sum(e.ataques_puntos for e in estadisticas) / sum(e.ataques_totales for e in estadisticas) * 100
            ) if sum(e.ataques_totales for e in estadisticas) > 0 else 0,
            "recepciones_perfectas": sum(e.recepciones_perfectas for e in estadisticas),
            "recepciones_positivas": sum(e.recepciones_positivas for e in estadisticas),
            "recepciones_fallidas": sum(e.recepciones_fallidas for e in estadisticas),
            "bloqueos_puntos": sum(e.bloqueos_puntos for e in estadisticas),
            "bloqueos_toques": sum(e.bloqueos_toques for e in estadisticas),
            "defensas_levantadas": sum(e.defensas_levantadas for e in estadisticas),
            "defensas_fallidas": sum(e.defensas_fallidas for e in estadisticas),
            "asistencias": sum(e.asistencias for e in estadisticas),
            "asistencias_fallidas": sum(e.asistencias_fallidas for e in estadisticas)
        }
    else:
        print("Error: Parámetros inválidos")
        return jsonify({"error": "Parámetros inválidos"}), 400

    # Generate charts (optimized for 2 rows, 3 per row)
    def generate_chart(data, labels, title, colors):
        try:
            plt.figure(figsize=(3, 2))
            plt.bar(labels, data, color=colors)
            plt.title(title, fontsize=8)
            plt.xlabel('Categorías', fontsize=6)
            plt.ylabel('Cantidad', fontsize=6)
            plt.xticks(fontsize=6, rotation=45)
            plt.yticks(fontsize=6)
            plt.tight_layout()
            img = BytesIO()
            plt.savefig(img, format='png', dpi=150)
            img.seek(0)
            plt.close()
            return img
        except Exception as e:
            print(f"Error generating chart {title}: {str(e)}")
            return None

    charts = {
        "saques": generate_chart(
            [datos["saques_ace"], datos["saques_fallidos"], datos["saques_totales"]],
            ["Ace", "Err.", "Total"], "Saques", ["#28a745", "#dc3545", "#007bff"]
        ),
        "ataques": generate_chart(
            [datos["ataques_puntos"], datos["ataques_fallidos"], datos["ataques_bloqueados"], datos["ataques_totales"]],
            ["Puntos", "Err.", "Bloq.", "Total"], "Ataques", ["#28a745", "#dc3545", "#ffc107", "#007bff"]
        ),
        "recepciones": generate_chart(
            [datos["recepciones_perfectas"], datos["recepciones_positivas"], datos["recepciones_fallidas"]],
            ["Perf.", "Pos.", "Err."], "Recepciones", ["#28a745", "#17a2b8", "#dc3545"]
        ),
        "bloqueos": generate_chart(
            [datos["bloqueos_puntos"], datos["bloqueos_toques"]],
            ["Puntos", "Toques"], "Bloqueos", ["#28a745", "#17a2b8"]
        ),
        "defensas": generate_chart(
            [datos["defensas_levantadas"], datos["defensas_fallidas"]],
            ["Lev.", "Err."], "Defensas", ["#28a745", "#dc3545"]
        ),
        "asistencias": generate_chart(
            [datos["asistencias"], datos["asistencias_fallidas"]],
            ["Asist.", "Err."], "Asistencias", ["#28a745", "#dc3545"]
        )
    }

    if any(chart is None for chart in charts.values()):
        return jsonify({"error": "Error al generar uno o más gráficos"}), 500

    # Create PDF in landscape mode
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=(letter[1], letter[0]))  # Landscape
    styles = getSampleStyleSheet()
    elements = []

    # Title
    title = f"Estadísticas de {'Jugador' if tipo != 'equipo' else 'Equipo'}: {datos.get('jugador', datos.get('equipo'))}"
    if tipo == 'por_partido':
        title += f" vs {datos['partido']}"
    title_style = styles['Title']
    title_style.fontSize = 14
    elements.append(Paragraph(title, title_style))
    elements.append(Spacer(1, 6))

    # Statistics Table (5 columns)
    stats_data = [
        ["S. Ace", str(datos["saques_ace"])],
        ["S. Fallidos", str(datos["saques_fallidos"])],
        ["S. Totales", str(datos["saques_totales"])],
        ["A. Puntos", str(datos["ataques_puntos"])],
        ["A. Fallidos", str(datos["ataques_fallidos"])],
        ["A. Bloqueados", str(datos["ataques_bloqueados"])],
        ["A. Totales", str(datos["ataques_totales"])],
        ["Ef. Ataque", f"{datos['efectividad_ataque']:.2f}%"],
        ["R. Perfectas", str(datos["recepciones_perfectas"])],
        ["R. Positivas", str(datos["recepciones_positivas"])],
        ["R. Fallidas", str(datos["recepciones_fallidas"])],
        ["B. Puntos", str(datos["bloqueos_puntos"])],
        ["B. Toques", str(datos["bloqueos_toques"])],
        ["D. Levantadas", str(datos["defensas_levantadas"])],
        ["D. Fallidas", str(datos["defensas_fallidas"])],
        ["Asistencias", str(datos["asistencias"])],
        ["A. Fallidas", str(datos["asistencias_fallidas"])]
    ]

    # Divide stats into 5 columns (4 rows each, including header)
    table_data = [
        ["Categoría", "Valor", "Categoría", "Valor", "Categoría", "Valor", "Categoría", "Valor", "Categoría", "Valor"]
    ]
    for i in range(3):  # 3 stats per column (plus header makes 4 rows)
        row = []
        for col in range(5):  # 5 columns
            idx = col * 3 + i
            if idx < len(stats_data):
                row.extend(stats_data[idx])
            else:
                row.extend(["", ""])  # Empty cells for padding
        table_data.append(row)

    table = Table(table_data, colWidths=[70, 30] * 5)  # 5 columns, each 70+30 points
    table.setStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 7),
        ('LEADING', (0, 0), (-1, -1), 8),
    ])
    elements.append(table)
    elements.append(Spacer(1, 6))

    # Charts (2 rows, 3 per row)
    chart_row_1 = []
    chart_row_2 = []
    chart_names = ["saques", "ataques", "recepciones", "bloqueos", "defensas", "asistencias"]
    for i, chart_name in enumerate(chart_names):
        img = Image(charts[chart_name], width=200, height=120)
        if i < 3:
            chart_row_1.append(img)
        else:
            chart_row_2.append(img)

    chart_table_1 = Table([chart_row_1], colWidths=[200] * 3, rowHeights=120)
    chart_table_2 = Table([chart_row_2], colWidths=[200] * 3, rowHeights=120)

    elements.append(chart_table_1)
    elements.append(Spacer(1, 6))
    elements.append(chart_table_2)

    # Build PDF
    try:
        doc.build(elements)
    except Exception as e:
        print(f"Error building PDF: {str(e)}")
        return jsonify({"error": f"Error al generar el PDF: {str(e)}"}), 500

    # Save to file with the same name as the title
    timestamp = int(time.time())
    file_name = re.sub(r'[^\w\s-]', '', title)  # Remove special characters
    file_name = re.sub(r'\s+', '_', file_name)  # Replace spaces with underscores
    file_name = f"{file_name}_{timestamp}.pdf"  # Add timestamp for uniqueness
    file_path = os.path.join('static', 'reports', file_name)
    try:
        with open(file_path, 'wb') as f:
            f.write(buffer.getvalue())
        print(f"PDF saved successfully: {file_path}")
    except Exception as e:
        print(f"Error saving PDF: {str(e)}")
        return jsonify({"error": f"Error al guardar el PDF: {str(e)}"}), 500

    return jsonify({"url": f"/{file_path}"})

# Rutas de exportación
@app.route('/partido/estadisticas/exportar/<int:partido_id>', methods=['POST'])
@login_required
def exportar_estadisticas(partido_id):
    partido = db.session.get(Partido, partido_id)
    if not partido or (partido.user_id != current_user.id and not current_user.is_admin):
        return jsonify({'error': 'Partido no encontrado o acceso denegado'}), 404
    jugador_id = request.form.get('jugador_id', '')
    return exportar_pdf()

@app.route('/reportes/exportar/pdf', methods=['POST'])
@login_required
def exportar_pdf_reportes():
    return exportar_pdf()

@app.route('/reportes')
@login_required
def ver_reportes():
    if current_user.is_admin:
        partidos = Partido.query.all()
        jugadores = Jugador.query.all()
        equipos = Equipo.query.all()
    else:
        partidos = Partido.query.filter_by(user_id=current_user.id).all()
        jugadores = Jugador.query.filter_by(user_id=current_user.id).all()
        equipos = Equipo.query.filter_by(user_id=current_user.id).all()
    return render_template('reportes.html', partidos=partidos, jugadores=jugadores, equipos=equipos)

@app.route('/api/estadisticas', methods=['GET'])
@login_required
def obtener_estadisticas():
    jugador_id = request.args.get('jugador_id')
    partido_id = request.args.get('partido_id')
    equipo_id = request.args.get('equipo_id')
    tipo = request.args.get('tipo')
    if tipo == 'por_partido' and jugador_id and partido_id:
        estadistica = EstadisticaPartido.query.filter_by(jugador_id=jugador_id, partido_id=partido_id).first()
        if not estadistica or (estadistica.user_id != current_user.id and not current_user.is_admin):
            return jsonify({"error": "Estadísticas no encontradas o acceso denegado"}), 404
        datos = {"jugador": estadistica.jugador.nombre, "partido": estadistica.partido.rival,
                 "saques_ace": estadistica.saques_ace,
                 "saques_fallidos": estadistica.saques_fallidos, "saques_totales": estadistica.saques_totales,
                 "ataques_puntos": estadistica.ataques_puntos, "ataques_fallidos": estadistica.ataques_fallidos,
                 "ataques_bloqueados": estadistica.ataques_bloqueados, "ataques_totales": estadistica.ataques_totales,
                 "efectividad_ataque": (
                             estadistica.ataques_puntos / estadistica.ataques_totales * 100) if estadistica.ataques_totales > 0 else 0,
                 "recepciones_perfectas": estadistica.recepciones_perfectas,
                 "recepciones_positivas": estadistica.recepciones_positivas,
                 "recepciones_fallidas": estadistica.recepciones_fallidas,
                 "bloqueos_puntos": estadistica.bloqueos_puntos,
                 "bloqueos_toques": estadistica.bloqueos_toques, "defensas_levantadas": estadistica.defensas_levantadas,
                 "defensas_fallidas": estadistica.defensas_fallidas, "asistencias": estadistica.asistencias,
                 "asistencias_fallidas": estadistica.asistencias_fallidas}
        return jsonify(datos)
    elif tipo == 'generales' and jugador_id:
        estadisticas = EstadisticaPartido.query.filter_by(jugador_id=jugador_id).all()
        if not estadisticas or (estadisticas[0].user_id != current_user.id and not current_user.is_admin):
            return jsonify({"error": "Estadísticas no encontradas o acceso denegado"}), 404
        datos = {"jugador": estadisticas[0].jugador.nombre,
                 "saques_ace": sum(e.saques_ace for e in estadisticas),
                 "saques_fallidos": sum(e.saques_fallidos for e in estadisticas),
                 "saques_totales": sum(e.saques_totales for e in estadisticas),
                 "ataques_puntos": sum(e.ataques_puntos for e in estadisticas),
                 "ataques_fallidos": sum(e.ataques_fallidos for e in estadisticas),
                 "ataques_bloqueados": sum(e.ataques_bloqueados for e in estadisticas),
                 "ataques_totales": sum(e.ataques_totales for e in estadisticas),
                 "efectividad_ataque": (sum(e.ataques_puntos for e in estadisticas) / sum(
                     e.ataques_totales for e in estadisticas) * 100) if sum(
                     e.ataques_totales for e in estadisticas) > 0 else 0,
                 "recepciones_perfectas": sum(e.recepciones_perfectas for e in estadisticas),
                 "recepciones_positivas": sum(e.recepciones_positivas for e in estadisticas),
                 "recepciones_fallidas": sum(e.recepciones_fallidas for e in estadisticas),
                 "bloqueos_puntos": sum(e.bloqueos_puntos for e in estadisticas),
                 "bloqueos_toques": sum(e.bloqueos_toques for e in estadisticas),
                 "defensas_levantadas": sum(e.defensas_levantadas for e in estadisticas),
                 "defensas_fallidas": sum(e.defensas_fallidas for e in estadisticas),
                 "asistencias": sum(e.asistencias for e in estadisticas),
                 "asistencias_fallidas": sum(e.asistencias_fallidas for e in estadisticas)}
        return jsonify(datos)
    elif tipo == 'equipo' and equipo_id:
        equipo = db.session.get(Equipo, equipo_id)
        if not equipo or (equipo.user_id != current_user.id and not current_user.is_admin):
            return jsonify({"error": "Equipo no encontrado o acceso denegado"}), 404
        jugadores = equipo.jugadores
        estadisticas = EstadisticaPartido.query.filter(
            EstadisticaPartido.jugador_id.in_([j.id for j in jugadores])).all()
        if not estadisticas:
            return jsonify({"error": "Estadísticas no encontradas"}), 404
        datos = {"equipo": equipo.nombre, "saques_ace": sum(e.saques_ace for e in estadisticas),
                 "saques_fallidos": sum(e.saques_fallidos for e in estadisticas),
                 "saques_totales": sum(e.saques_totales for e in estadisticas),
                 "ataques_puntos": sum(e.ataques_puntos for e in estadisticas),
                 "ataques_fallidos": sum(e.ataques_fallidos for e in estadisticas),
                 "ataques_bloqueados": sum(e.ataques_bloqueados for e in estadisticas),
                 "ataques_totales": sum(e.ataques_totales for e in estadisticas),
                 "efectividad_ataque": (sum(e.ataques_puntos for e in estadisticas) / sum(
                     e.ataques_totales for e in estadisticas) * 100) if sum(
                     e.ataques_totales for e in estadisticas) > 0 else 0,
                 "recepciones_perfectas": sum(e.recepciones_perfectas for e in estadisticas),
                 "recepciones_positivas": sum(e.recepciones_positivas for e in estadisticas),
                 "recepciones_fallidas": sum(e.recepciones_fallidas for e in estadisticas),
                 "bloqueos_puntos": sum(e.bloqueos_puntos for e in estadisticas),
                 "bloqueos_toques": sum(e.bloqueos_toques for e in estadisticas),
                 "defensas_levantadas": sum(e.defensas_levantadas for e in estadisticas),
                 "defensas_fallidas": sum(e.defensas_fallidas for e in estadisticas),
                 "asistencias": sum(e.asistencias for e in estadisticas),
                 "asistencias_fallidas": sum(e.asistencias_fallidas for e in estadisticas)}
        return jsonify(datos)
    return jsonify({"error": "Parámetros inválidos"}), 400

@app.route('/update_stat', methods=['POST'])
@login_required
def update_stat():
    data = request.get_json()
    partido_id = data['partido_id']
    jugador_id = data['jugador_id']
    stat = data['stat']
    action = data['action']
    partido = db.session.get(Partido, partido_id)
    if not partido or (partido.user_id != current_user.id and not current_user.is_admin):
        return jsonify({'error': 'Unauthorized'}), 403
    estadistica = EstadisticaPartido.query.filter_by(partido_id=partido_id, jugador_id=jugador_id).first()
    if not estadistica:
        estadistica = EstadisticaPartido(partido_id=partido_id, jugador_id=jugador_id, user_id=current_user.id)
        db.session.add(estadistica)
    if action == 'increment':
        current_value = getattr(estadistica, stat, 0)
        setattr(estadistica, stat, current_value + 1)
        if stat.startswith('saques_'):
            estadistica.saques_totales = estadistica.saques_ace + estadistica.saques_fallidos
        elif stat.startswith('ataques_'):
            estadistica.ataques_totales = estadistica.ataques_puntos + estadistica.ataques_fallidos + estadistica.ataques_bloqueados
    elif action == 'decrement':
        current_value = getattr(estadistica, stat, 0)
        if current_value > 0:
            setattr(estadistica, stat, current_value - 1)
            if stat.startswith('saques_'):
                estadistica.saques_totales = estadistica.saques_ace + estadistica.saques_fallidos
            elif stat.startswith('ataques_'):
                estadistica.ataques_totales = estadistica.ataques_puntos + estadistica.ataques_fallidos + estadistica.ataques_bloqueados
    db.session.commit()
    event_data = {
        'jugador_id': jugador_id, 'stat': stat, 'value': getattr(estadistica, stat),
        'saques_totales': estadistica.saques_totales, 'ataques_totales': estadistica.ataques_totales,
        'efectividad_ataque': (estadistica.ataques_puntos / estadistica.ataques_totales * 100) if estadistica.ataques_totales > 0 else 0,
        'recepciones_perfectas': estadistica.recepciones_perfectas,
        'recepciones_positivas': estadistica.recepciones_positivas,
        'recepciones_fallidas': estadistica.recepciones_fallidas, 'bloqueos_puntos': estadistica.bloqueos_puntos,
        'bloqueos_toques': estadistica.bloqueos_toques, 'defensas_levantadas': estadistica.defensas_levantadas,
        'defensas_fallidas': estadistica.defensas_fallidas, 'asistencias': estadistica.asistencias,
        'asistencias_fallidas': estadistica.asistencias_fallidas
    }
    broadcast_event('stat_updated', event_data)
    return jsonify({'message': 'Stat updated'})

@app.route('/update_score', methods=['POST'])
@login_required
def update_score():
    data = request.get_json()
    partido_id = data['partido_id']
    scoreLocal = data['scoreLocal']
    scoreVisitante = data['scoreVisitante']
    set_scores = data.get('set_scores', [])
    partido = db.session.get(Partido, partido_id)
    if not partido or (partido.user_id != current_user.id and not current_user.is_admin):
        return jsonify({'error': 'Unauthorized'}), 403
    partido.marcador_local = scoreLocal
    partido.marcador_visitante = scoreVisitante
    partido.set_scores = set_scores
    db.session.commit()
    broadcast_event('score_updated', {
        'partido_id': partido_id, 'scoreLocal': scoreLocal, 'scoreVisitante': scoreVisitante, 'set_scores': set_scores
    })
    return jsonify({'message': 'Score updated'})

@app.route('/update_titulares', methods=['POST'])
@login_required
def update_titulares():
    data = request.get_json()
    partido_id = data['partido_id']
    jugador_id = data['jugador_id']
    action = data['action']
    posicion = data.get('posicion', 1)
    partido = db.session.get(Partido, partido_id)
    if not partido or (partido.user_id != current_user.id and not current_user.is_admin):
        return jsonify({'error': 'Unauthorized'}), 403
    if action == 'add':
        if len(partido.titulares) >= 7:
            broadcast_event('titulares_error', {'message': 'No se pueden tener más de 7 jugadores en cancha.'})
            return jsonify({'error': 'Too many players'}), 400
        if jugador_id not in partido.titulares:
            partido.titulares.append(jugador_id)
            estadistica = EstadisticaPartido.query.filter_by(partido_id=partido_id, jugador_id=jugador_id).first()
            if not estadistica:
                estadistica = EstadisticaPartido(partido_id=partido_id, jugador_id=jugador_id, user_id=current_user.id, posicion=posicion)
                db.session.add(estadistica)
            else:
                estadistica.posicion = posicion
    elif action == 'remove':
        if jugador_id in partido.titulares:
            partido.titulares.remove(jugador_id)
    db.session.commit()
    broadcast_event('titulares_updated', {
        'partido_id': partido_id, 'titulares': partido.titulares, 'jugador_id': jugador_id, 'posicion': posicion, 'action': action
    })
    return jsonify({'message': 'Titulares updated'})

@app.route('/rotate_positions', methods=['POST'])
@login_required
def rotate_positions():
    data = request.get_json()
    partido_id = data['partido_id']
    partido = db.session.get(Partido, partido_id)
    if not partido or (partido.user_id != current_user.id and not current_user.is_admin):
        return jsonify({'error': 'Unauthorized'}), 403
    estadisticas = EstadisticaPartido.query.filter_by(partido_id=partido_id).all()
    for stat in estadisticas:
        if stat.jugador_id in partido.titulares:
            stat.posicion = (stat.posicion % 7) + 1
    db.session.commit()
    posiciones = {stat.jugador_id: stat.posicion for stat in estadisticas if stat.jugador_id in partido.titulares}
    broadcast_event('positions_rotated', {'partido_id': partido_id, 'posiciones': posiciones})
    return jsonify({'message': 'Positions rotated'})

@app.route('/partido/estadisticas/grabar/<int:partido_id>', methods=['POST'])
@login_required
def grabar_partido(partido_id):
    partido = db.session.get(Partido, partido_id)
    if not partido or (partido.user_id != current_user.id and not current_user.is_admin):
        return jsonify({'error': 'Partido no encontrado o acceso denegado'}), 404
    estadisticas = EstadisticaPartido.query.filter_by(partido_id=partido_id).all()
    for estadistica in estadisticas:
        estadistica.saques_ace = 0
        estadistica.saques_fallidos = 0
        estadistica.saques_totales = 0
        estadistica.ataques_puntos = 0
        estadistica.ataques_fallidos = 0
        estadistica.ataques_bloqueados = 0
        estadistica.ataques_totales = 0
        estadistica.recepciones_perfectas = 0
        estadistica.recepciones_positivas = 0
        estadistica.recepciones_fallidas = 0
        estadistica.bloqueos_puntos = 0
        estadistica.bloqueos_toques = 0
        estadistica.defensas_levantadas = 0
        estadistica.defensas_fallidas = 0
        estadistica.asistencias = 0
        estadistica.asistencias_fallidas = 0
        estadistica.posicion = 1
        estadistica.notas = None
    partido.titulares = []
    partido.estado = "Finalizado"
    partido.marcador_local = 0
    partido.marcador_visitante = 0
    db.session.commit()
    return jsonify({'message': 'Partido grabado y estadísticas reiniciadas'})

@app.route('/tablero')
@login_required
def mostrar_tablero():
    return render_template('tablero.html')

# Crear tablas y usuario admin inicial
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', email='admin@example.com', is_admin=True)
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)