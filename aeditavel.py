import json
import os
import re
from datetime import datetime
import locale
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import (SocketIO)
import threading
import webbrowser
import time
import os

# Configurar locale para português
try:
    locale.setlocale(locale.LC_ALL, 'pt_BR.UTF-8')
except:
    locale.setlocale(locale.LC_ALL, 'Portuguese_Brazil')

app = Flask(__name__)
app.secret_key = 'sua_chave_secreta_aqui'  # Troque por uma chave secreta forte
socketio = SocketIO(app)

# Configurações de arquivos
DEMANDAS_FILE = "dados/demandas.json"
USERS_FILE = "users.json"
AGENDAMENTOS_FILE = "dados/agendamentos.json"

# Cores modernas
COLORS = {
    "primary": "#4a6fa5",
    "secondary": "#166088",
    "accent": "#4fc3f7",
    "background": "#f5f7fa",
    "text": "#333333",
    "success": "#4caf50",
    "warning": "#ff9800",
    "danger": "#f44336",
    "light": "#ffffff",
    "dark": "#263238"
}


# Funções auxiliares
def carregar_demandas():
    if not os.path.exists(DEMANDAS_FILE):
        return []
    with open(DEMANDAS_FILE, "r", encoding='utf-8') as f:
        return json.load(f)


def salvar_demandas(demandas):
    with open(DEMANDAS_FILE, "w", encoding='utf-8') as f:
        json.dump(demandas, f, indent=4, ensure_ascii=False)


def carregar_usuarios():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r", encoding='utf-8') as f:
        return json.load(f)


def salvar_usuarios(usuarios):
    with open(USERS_FILE, "w", encoding='utf-8') as f:
        json.dump(usuarios, f, indent=4, ensure_ascii=False)


def carregar_agendamentos():
    if not os.path.exists(AGENDAMENTOS_FILE):
        return {}
    with open(AGENDAMENTOS_FILE, "r", encoding='utf-8') as f:
        return json.load(f)


def salvar_agendamentos(agendamentos):
    with open(AGENDAMENTOS_FILE, "w", encoding='utf-8') as f:
        json.dump(agendamentos, f, indent=4, ensure_ascii=False)


def is_url(texto):
    """Verifica se o texto contém uma URL"""
    padrao_url = re.compile(
        r'^(?:http|ftp)s?://'  # http:// ou https://
        r'(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+'  # domínio
        r'(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)'  # TLD
        r'(?:/?|[/?]\S*)$', re.IGNORECASE)  # caminho, query string, etc.
    return re.match(padrao_url, texto) is not None


def verificar_acesso(usuario, tipo_acesso):
    if usuario == "admin":
        return True

    if not os.path.exists("dados/acessos.json"):
        return False

    with open("dados/acessos.json", "r", encoding='utf-8') as f:
        acessos = json.load(f)

    return acessos.get(usuario, {}).get(tipo_acesso, False)


def get_status_color(status):
    if status == "Aguardando Resposta":
        return COLORS['warning']
    elif status == "Em Andamento":
        return COLORS['accent']
    elif status == "Executado":
        return COLORS['success']
    elif status == "Redirecionada":
        return COLORS['danger']
    else:
        return COLORS['text']


# Rotas Flask
@app.route('/')
def index():
    session['usuario'] = 'admin'  # Auto-login para testes
    return redirect(url_for('painel'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        usuario = request.form.get('usuario')
        senha = request.form.get('senha')

        usuarios = carregar_usuarios()

        if usuario in usuarios and check_password_hash(usuarios[usuario], senha):
            session['usuario'] = usuario
            return redirect(url_for('painel'))
        else:
            return render_template('login.html', error="Usuário ou senha inválidos")

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('usuario', None)
    return redirect(url_for('login'))


@app.route('/painel')
def painel():
    if 'usuario' not in session:
        return redirect(url_for('login'))

    usuario = session['usuario']
    demandas = carregar_demandas()
    agendamentos = carregar_agendamentos()

    # Filtrar demandas recebidas
    demandas_recebidas = [d for d in demandas if d["destino"] == usuario]

    # Filtrar demandas enviadas
    demandas_enviadas = [d for d in demandas if d["origem"] == usuario]

    # Obter agendamentos do mês atual
    hoje = datetime.now()
    mes_atual = hoje.month
    ano_atual = hoje.year
    agendamentos_mes = []

    for data, eventos in agendamentos.items():
        try:
            data_evento = datetime.strptime(data, "%Y-%m-%d")
            if data_evento.month == mes_atual and data_evento.year == ano_atual:
                for evento in eventos:
                    data_formatada = data_evento.strftime("%d/%m/%Y")
                    agendamentos_mes.append(
                        (data_evento, f"{data_formatada} - {evento['motivo']} - {evento['usuario']}"))
        except:
            continue

    # Ordenar por data
    agendamentos_mes.sort(key=lambda x: x[0])
    agendamentos_mes = [evento[1] for evento in agendamentos_mes]

    # Verificar se o usuário tem acesso administrativo
    acesso_total = verificar_acesso(usuario, "acesso_total")
    gerenciar_usuarios = verificar_acesso(usuario, "gerenciar_usuarios")

    return render_template('painel.html',
                           usuario=usuario,
                           demandas_recebidas=demandas_recebidas,
                           demandas_enviadas=demandas_enviadas,
                           agendamentos=agendamentos_mes,
                           colors=COLORS,
                           acesso_total=acesso_total,
                           gerenciar_usuarios=gerenciar_usuarios)


@app.route('/solicitar-demanda', methods=['GET', 'POST'])
def solicitar_demanda():
    if 'usuario' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        destino = request.form.get('destino')
        descricao = request.form.get('descricao')

        if not destino or not descricao:
            return render_template('solicitar_demanda.html',
                                   usuarios=carregar_usuarios(),
                                   error="Preencha todos os campos")

        nova = {
            "origem": session['usuario'],
            "destino": destino,
            "descricao": descricao,
            "status": "Aguardando Resposta",
            "observacao": "",
            "prazo": "",
            "data_envio": str(datetime.now()),
            "historico": [f"Demanda criada por {session['usuario']} em {datetime.now().strftime('%d/%m/%Y %H:%M')}"]
        }

        demandas = carregar_demandas()
        demandas.append(nova)
        salvar_demandas(demandas)

        socketio.emit('atualizar_demandas', {'usuario': destino})

        return redirect(url_for('painel'))

    usuarios = carregar_usuarios()
    # Remover o próprio usuário da lista de destinos
    usuarios = [u for u in usuarios.keys() if u != session['usuario']]

    return render_template('solicitar_demanda.html', usuarios=usuarios)


@app.route('/demandas-recebidas')
def demandas_recebidas():
    if 'usuario' not in session:
        return redirect(url_for('login'))

    usuario = session['usuario']
    demandas = carregar_demandas()
    demandas_recebidas = [d for d in demandas if d["destino"] == usuario]

    return render_template('demandas_recebidas.html',
                           demandas=demandas_recebidas,
                           colors=COLORS,
                           get_status_color=get_status_color)


@app.route('/demandas-enviadas')
def demandas_enviadas():
    if 'usuario' not in session:
        return redirect(url_for('login'))

    usuario = session['usuario']
    demandas = carregar_demandas()
    demandas_enviadas = [d for d in demandas if d["origem"] == usuario]

    return render_template('demandas_enviadas.html',
                           demandas=demandas_enviadas,
                           colors=COLORS,
                           get_status_color=get_status_color)


@app.route('/todas-demandas')
def todas_demandas():
    if 'usuario' not in session:
        return redirect(url_for('login'))

    if not verificar_acesso(session['usuario'], "acesso_total"):
        return redirect(url_for('painel'))

    demandas = carregar_demandas()

    return render_template('todas_demandas.html',
                           demandas=demandas,
                           colors=COLORS,
                           get_status_color=get_status_color)


@app.route('/assumir-demanda/<int:demanda_id>', methods=['GET', 'POST'])
def assumir_demanda(demanda_id):
    if 'usuario' not in session:
        return redirect(url_for('login'))

    demandas = carregar_demandas()

    if demanda_id < 0 or demanda_id >= len(demandas):
        return redirect(url_for('demandas_recebidas'))

    demanda = demandas[demanda_id]

    if demanda['destino'] != session['usuario']:
        return redirect(url_for('demandas_recebidas'))

    if request.method == 'POST':
        prazo = request.form.get('prazo')

        if not prazo:
            return render_template('assumir_demanda.html',
                                   demanda=demanda,
                                   demanda_id=demanda_id,
                                   error="Informe um prazo")

        demanda["status"] = "Em Andamento"
        demanda["prazo"] = prazo
        demanda["historico"].append(
            f"{session['usuario']} assumiu com prazo até {prazo} em {datetime.now().strftime('%d/%m/%Y %H:%M')}")

        salvar_demandas(demandas)
        socketio.emit('atualizar_demandas', {'usuario': session['usuario']})

        return redirect(url_for('demandas_recebidas'))

    return render_template('assumir_demanda.html', demanda=demanda, demanda_id=demanda_id)


@app.route('/concluir-demanda/<int:demanda_id>', methods=['GET', 'POST'])
def concluir_demanda(demanda_id):
    if 'usuario' not in session:
        return redirect(url_for('login'))

    demandas = carregar_demandas()

    if demanda_id < 0 or demanda_id >= len(demandas):
        return redirect(url_for('demandas_recebidas'))

    demanda = demandas[demanda_id]

    if demanda['destino'] != session['usuario'] or demanda['status'] != "Em Andamento":
        return redirect(url_for('demandas_recebidas'))

    if request.method == 'POST':
        observacao = request.form.get('observacao')

        if not observacao:
            return render_template('concluir_demanda.html',
                                   demanda=demanda,
                                   demanda_id=demanda_id,
                                   error="Descreva o que foi realizado")

        demanda["status"] = "Executado"
        demanda["observacao"] = observacao
        demanda["historico"].append(
            f"{session['usuario']} concluiu em {datetime.now().strftime('%d/%m/%Y %H:%M')} com observação: {observacao}")

        salvar_demandas(demandas)
        socketio.emit('atualizar_demandas', {'usuario': session['usuario']})

        return redirect(url_for('demandas_recebidas'))

    return render_template('concluir_demanda.html', demanda=demanda, demanda_id=demanda_id)


@app.route('/redirecionar-demanda/<int:demanda_id>', methods=['GET', 'POST'])
def redirecionar_demanda(demanda_id):
    if 'usuario' not in session:
        return redirect(url_for('login'))

    demandas = carregar_demandas()

    if demanda_id < 0 or demanda_id >= len(demandas):
        return redirect(url_for('demandas_recebidas'))

    demanda = demandas[demanda_id]

    if demanda['destino'] != session['usuario']:
        return redirect(url_for('demandas_recebidas'))

    usuarios = carregar_usuarios()
    # Lista de setores permitidos para redirecionamento
    setores_permitidos = ["Gerencia", "Bruna", "Vera", "Coordenação", "Recepção", "Dosagem"]
    # Remover o próprio usuário da lista
    setores = [u for u in setores_permitidos if u != session['usuario']]

    if request.method == 'POST':
        novo_setor = request.form.get('novo_setor')

        if not novo_setor or novo_setor not in setores:
            return render_template('redirecionar_demanda.html',
                                   demanda=demanda,
                                   demanda_id=demanda_id,
                                   setores=setores,
                                   error="Selecione um setor válido")

        demanda["destino"] = novo_setor
        demanda["status"] = "Redirecionada"
        acao = f"{session['usuario']} redirecionou para {novo_setor} em {datetime.now().strftime('%d/%m/%Y %H:%M')}"
        demanda["historico"].append(acao)

        salvar_demandas(demandas)
        socketio.emit('atualizar_demandas', {'usuario': novo_setor})

        return redirect(url_for('demandas_recebidas'))

    return render_template('redirecionar_demanda.html',
                           demanda=demanda,
                           demanda_id=demanda_id,
                           setores=setores)


@app.route('/agendamentos')
def agendamentos():
    if 'usuario' not in session:
        return redirect(url_for('login'))

    agendamentos = carregar_agendamentos()
    hoje = datetime.now()
    mes_atual = hoje.month
    ano_atual = hoje.year
    agendamentos_mes = []

    for data, eventos in agendamentos.items():
        try:
            data_evento = datetime.strptime(data, "%Y-%m-%d")
            if data_evento.month == mes_atual and data_evento.year == ano_atual:
                for evento in eventos:
                    data_formatada = data_evento.strftime("%d/%m/%Y")
                    agendamentos_mes.append(
                        (data_evento, f"{data_formatada} - {evento['motivo']} - {evento['usuario']}"))
        except:
            continue

    # Ordenar por data
    agendamentos_mes.sort(key=lambda x: x[0])
    agendamentos_mes = [evento[1] for evento in agendamentos_mes]

    return render_template('agendamentos.html', agendamentos=agendamentos_mes)


@app.route('/adicionar-agendamento', methods=['GET', 'POST'])
def adicionar_agendamento():
    if 'usuario' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        data = request.form.get('data')
        motivo = request.form.get('motivo')

        if not data or not motivo:
            return render_template('adicionar_agendamento.html', error="Preencha todos os campos")

        try:
            # Converter data do formato dd/mm/yyyy para yyyy-mm-dd
            data_obj = datetime.strptime(data, "%d/%m/%Y")
            data_formatada = data_obj.strftime("%Y-%m-%d")
        except Exception as e:
            return render_template('adicionar_agendamento.html', error=f"Data inválida: {str(e)}")

        agendamentos = carregar_agendamentos()

        if data_formatada not in agendamentos:
            agendamentos[data_formatada] = []

        agendamentos[data_formatada].append({
            "usuario": session['usuario'],
            "motivo": motivo,
            "data": data_formatada
        })

        salvar_agendamentos(agendamentos)
        socketio.emit('atualizar_agendamentos', {})

        return redirect(url_for('agendamentos'))

    hoje = datetime.now().strftime("%d/%m/%Y")
    return render_template('adicionar_agendamento.html', hoje=hoje)


@app.route('/excluir-agendamento/<string:data>/<int:index>')
def excluir_agendamento(data, index):
    if 'usuario' not in session:
        return redirect(url_for('login'))

    agendamentos = carregar_agendamentos()

    if data in agendamentos and 0 <= index < len(agendamentos[data]):
        # Verificar se o usuário tem permissão para excluir
        agendamento = agendamentos[data][index]
        if agendamento['usuario'] != session['usuario'] and session['usuario'] not in ["Bruna", "Vera", "Ludson",
                                                                                       "admin"]:
            return redirect(url_for('agendamentos'))

        del agendamentos[data][index]

        # Se não houver mais agendamentos nessa data, remover a data do dicionário
        if not agendamentos[data]:
            del agendamentos[data]

        salvar_agendamentos(agendamentos)
        socketio.emit('atualizar_agendamentos', {})

    return redirect(url_for('agendamentos'))


@app.route('/gerenciar-usuarios')
def gerenciar_usuarios():
    if 'usuario' not in session:
        return redirect(url_for('login'))

    if not verificar_acesso(session['usuario'], "gerenciar_usuarios"):
        return redirect(url_for('painel'))

    usuarios = carregar_usuarios()

    # Carregar configurações de acesso
    if not os.path.exists("dados/acessos.json"):
        acessos = {}
    else:
        with open("dados/acessos.json", "r", encoding='utf-8') as f:
            acessos = json.load(f)

    # Adicionar informações de acesso aos usuários
    usuarios_info = []
    for usuario in sorted(usuarios.keys()):
        acesso_total = acessos.get(usuario, {}).get("acesso_total", False)
        gerenciar_usuarios = acessos.get(usuario, {}).get("gerenciar_usuarios", False)
        usuarios_info.append({
            'nome': usuario,
            'acesso_total': acesso_total,
            'gerenciar_usuarios': gerenciar_usuarios
        })

    return render_template('gerenciar_usuarios.html', usuarios=usuarios_info)


@app.route('/adicionar-usuario', methods=['GET', 'POST'])
def adicionar_usuario():
    if 'usuario' not in session:
        return redirect(url_for('login'))

    if not verificar_acesso(session['usuario'], "gerenciar_usuarios"):
        return redirect(url_for('painel'))

    if request.method == 'POST':
        novo_usuario = request.form.get('usuario').strip()
        senha = request.form.get('senha').strip()
        confirmar_senha = request.form.get('confirmar_senha').strip()

        if not novo_usuario or not senha:
            return render_template('adicionar_usuario.html', error="Preencha todos os campos")

        if senha != confirmar_senha:
            return render_template('adicionar_usuario.html', error="As senhas não coincidem")

        usuarios = carregar_usuarios()

        if novo_usuario in usuarios:
            return render_template('adicionar_usuario.html', error="Este usuário já existe")

        usuarios[novo_usuario] = generate_password_hash(senha)
        salvar_usuarios(usuarios)

        return redirect(url_for('gerenciar_usuarios'))

    return render_template('adicionar_usuario.html')


@app.route('/remover-usuario/<string:usuario>')
def remover_usuario(usuario):
    if 'usuario' not in session:
        return redirect(url_for('login'))

    if not verificar_acesso(session['usuario'], "gerenciar_usuarios"):
        return redirect(url_for('painel'))

    if usuario == "admin":
        return redirect(url_for('gerenciar_usuarios'))

    usuarios = carregar_usuarios()

    if usuario in usuarios:
        del usuarios[usuario]
        salvar_usuarios(usuarios)

        # Remover também dos acessos se existir
        if os.path.exists("dados/acessos.json"):
            with open("dados/acessos.json", "r", encoding='utf-8') as f:
                acessos = json.load(f)

            if usuario in acessos:
                del acessos[usuario]

                with open("dados/acessos.json", "w", encoding='utf-8') as f:
                    json.dump(acessos, f, indent=4)

    return redirect(url_for('gerenciar_usuarios'))


@app.route('/redefinir-senha/<string:usuario>', methods=['GET', 'POST'])
def redefinir_senha(usuario):
    if 'usuario' not in session:
        return redirect(url_for('login'))

    if not verificar_acesso(session['usuario'], "gerenciar_usuarios"):
        return redirect(url_for('painel'))

    usuarios = carregar_usuarios()

    if usuario not in usuarios:
        return redirect(url_for('gerenciar_usuarios'))

    if request.method == 'POST':
        senha = request.form.get('senha').strip()
        confirmar_senha = request.form.get('confirmar_senha').strip()

        if not senha:
            return render_template('redefinir_senha.html', usuario=usuario, error="Informe uma nova senha")

        if senha != confirmar_senha:
            return render_template('redefinir_senha.html', usuario=usuario, error="As senhas não coincidem")

        usuarios[usuario] = generate_password_hash(senha)
        salvar_usuarios(usuarios)

        return redirect(url_for('gerenciar_usuarios'))

    return render_template('redefinir_senha.html', usuario=usuario)


@app.route('/liberar-acessos/<string:usuario>', methods=['GET', 'POST'])
def liberar_acessos(usuario):
    if 'usuario' not in session:
        return redirect(url_for('login'))

    if not verificar_acesso(session['usuario'], "gerenciar_usuarios"):
        return redirect(url_for('painel'))

    if usuario == "admin":
        return redirect(url_for('gerenciar_usuarios'))

    if request.method == 'POST':
        acesso_total = request.form.get('acesso_total') == 'on'
        gerenciar_usuarios = request.form.get('gerenciar_usuarios') == 'on'

        # Carregar configurações existentes
        if not os.path.exists("dados/acessos.json"):
            acessos = {}
        else:
            with open("dados/acessos.json", "r", encoding='utf-8') as f:
                acessos = json.load(f)

        # Atualizar configurações de acesso
        acessos[usuario] = {
            "acesso_total": acesso_total,
            "gerenciar_usuarios": gerenciar_usuarios
        }

        # Salvar no arquivo
        with open("dados/acessos.json", "w", encoding='utf-8') as f:
            json.dump(acessos, f, indent=4)

        return redirect(url_for('gerenciar_usuarios'))

    # Carregar configurações existentes
    if not os.path.exists("dados/acessos.json"):
        acessos = {}
    else:
        with open("dados/acessos.json", "r", encoding='utf-8') as f:
            acessos = json.load(f)

    user_access = acessos.get(usuario, {})

    return render_template('liberar_acessos.html',
                           usuario=usuario,
                           acesso_total=user_access.get("acesso_total", False),
                           gerenciar_usuarios=user_access.get("gerenciar_usuarios", False))


# Eventos SocketIO
@socketio.on('connect')
def handle_connect():
    print('Cliente conectado')


# Inicialização
def criar_arquivos_iniciais():
    os.makedirs("dados", exist_ok=True)

    if not os.path.exists(USERS_FILE):
        usuarios = {
            "admin": generate_password_hash("admin123"),
            "Bruna": generate_password_hash("123"),
            "Vera": generate_password_hash("123"),
            "Ludson": generate_password_hash("123"),
            "Gerencia": generate_password_hash("123"),
            "Coordenação": generate_password_hash("123"),
            "Recepção": generate_password_hash("123"),
            "Dosagem": generate_password_hash("123")
        }
        with open(USERS_FILE, "w", encoding='utf-8') as f:
            json.dump(usuarios, f, indent=4)

    if not os.path.exists(DEMANDAS_FILE):
        with open(DEMANDAS_FILE, "w", encoding='utf-8') as f:
            json.dump([], f)

    if not os.path.exists(AGENDAMENTOS_FILE):
        with open(AGENDAMENTOS_FILE, "w", encoding='utf-8') as f:
            json.dump({}, f)

    if not os.path.exists("dados/acessos.json"):
        acessos = {
            "admin": {
                "acesso_total": True,
                "gerenciar_usuarios": True
            },
            "Bruna": {
                "acesso_total": True,
                "gerenciar_usuarios": True
            },
            "Vera": {
                "acesso_total": True,
                "gerenciar_usuarios": True
            },
            "Ludson": {
                "acesso_total": True,
                "gerenciar_usuarios": True
            }
        }
        with open("dados/acessos.json", "w", encoding='utf-8') as f:
            json.dump(acessos, f, indent=4)


def abrir_navegador():
    time.sleep(1)
    webbrowser.open_new('http://127.0.0.1:5000/')


if __name__ == '__main__':
    criar_arquivos_iniciais()
    app.run(host='0.0.0.0', port=5000, debug=True)

    # Iniciar navegador automaticamente
    threading.Thread(target=abrir_navegador).start()

    # Executar aplicação Flask
    socketio.run(app, debug=True)