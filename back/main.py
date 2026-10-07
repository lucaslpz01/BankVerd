from __future__ import annotations

import hashlib
import hmac
import json
import os
import random
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from pathlib import Path

ZERO = Decimal("0.00")



class BancoErro(Exception):
    pass



class AutenticacaoErro(BancoErro):
    pass


class ValorInvalidoErro(BancoErro):
    pass


class SaldoInsuficienteErro(BancoErro):
    pass


class ChavePixErro(BancoErro):
    pass


class CartaoErro(BancoErro):
    pass



def dinheiro(valor) -> Decimal:
    try:
        d = Decimal(str(valor).strip().replace(",", "."))
    except InvalidOperation:
        raise ValorInvalidoErro("Valor inválido.")
    return d.quantize(Decimal("0.01"), ROUND_HALF_UP)


def valor_positivo(valor) -> Decimal:
    d = dinheiro(valor)
    if d <= 0:
        raise ValorInvalidoErro("O valor deve ser maior que zero.")
    return d


def formatar(valor: Decimal) -> str:
    texto = f"{valor:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
    return f"R$ {texto}"


def _hash_senha(senha: str, salt: str | None = None) -> tuple[str, str]:
    salt = salt or os.urandom(16).hex()
    h = hashlib.pbkdf2_hmac("sha256", senha.encode(), bytes.fromhex(salt), 100_000)
    return salt, h.hex()



@dataclass
class Transacao:
    tipo: str
    valor: Decimal
    descricao: str
    saldo_apos: Decimal
    data: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])


@dataclass
class Cartao:
    final: str
    bandeira: str
    limite: Decimal
    fatura: Decimal = ZERO
    bloqueado: bool = False

    @property
    def disponivel(self) -> Decimal:
        return self.limite - self.fatura


@dataclass
class Conta:
    titular: str
    usuario: str
    salt: str
    senha_hash: str
    numero: str
    saldo: Decimal = ZERO
    cofrinho: Decimal = ZERO
    limite_pix_diario: Decimal = Decimal("5000.00")
    chaves_pix: dict = field(default_factory=dict)
    cartoes: list = field(default_factory=list)
    transacoes: list = field(default_factory=list)
    tentativas_falhas: int = 0
    bloqueada: bool = False

    # ---------------- segurança ----------------
    def verificar_senha(self, senha: str) -> bool:
        _, h = _hash_senha(senha, self.salt)
        return hmac.compare_digest(h, self.senha_hash)

    def trocar_senha(self, atual: str, nova: str) -> None:
        if not self.verificar_senha(atual):
            raise AutenticacaoErro("Senha atual incorreta.")
        if len(nova) < 6:
            raise AutenticacaoErro("A nova senha deve ter pelo menos 6 caracteres.")
        self.salt, self.senha_hash = _hash_senha(nova)

    # ---------------- interno ----------------
    def _registrar(self, tipo: str, valor: Decimal, descricao: str = "") -> Transacao:
        t = Transacao(tipo, valor, descricao, self.saldo)
        self.transacoes.append(t)
        return t

    def _debitar(self, valor: Decimal) -> None:
        if valor > self.saldo:
            raise SaldoInsuficienteErro(
                f"Saldo insuficiente. Disponível: {formatar(self.saldo)}"
            )
        self.saldo -= valor

    # ---------------- operações básicas ----------------
    def depositar(self, valor) -> Transacao:
        valor = valor_positivo(valor)
        self.saldo += valor
        return self._registrar("Depósito", valor)

    def sacar(self, valor) -> Transacao:
        valor = valor_positivo(valor)
        self._debitar(valor)
        return self._registrar("Saque", -valor)

    def extrato(self, quantidade: int | None = None, tipo: str | None = None) -> list:
        """Mais recentes primeiro. Filtros opcionais por quantidade e tipo."""
        itens = [t for t in self.transacoes if tipo is None or t.tipo == tipo]
        itens = list(reversed(itens))
        return itens[:quantidade] if quantidade else itens

    # ---------------- Pix ----------------
    def registrar_chave_pix(self, tipo: str, valor: str | None = None) -> str:
        tipo = tipo.lower()
        if tipo not in ("cpf", "email", "telefone", "aleatoria"):
            raise ChavePixErro("Tipo de chave inválido (cpf, email, telefone ou aleatoria).")
        if tipo in self.chaves_pix:
            raise ChavePixErro(f"Você já tem uma chave do tipo {tipo}.")
        chave = str(uuid.uuid4()) if tipo == "aleatoria" else (valor or "").strip().lower()
        if not chave:
            raise ChavePixErro("Informe o valor da chave.")
        self.chaves_pix[tipo] = chave
        return chave

    def remover_chave_pix(self, tipo: str) -> None:
        if self.chaves_pix.pop(tipo.lower(), None) is None:
            raise ChavePixErro("Chave não encontrada.")

    def pix_enviado_hoje(self) -> Decimal:
        hoje = datetime.now().date().isoformat()
        return sum(
            (-t.valor for t in self.transacoes if t.tipo == "Pix enviado" and t.data[:10] == hoje),
            ZERO,
        )

    def debitar_pix(self, valor, destinatario: str) -> Decimal:
        valor = valor_positivo(valor)
        if self.pix_enviado_hoje() + valor > self.limite_pix_diario:
            raise ValorInvalidoErro(
                f"Limite diário de Pix excedido ({formatar(self.limite_pix_diario)})."
            )
        self._debitar(valor)
        self._registrar("Pix enviado", -valor, f"Para {destinatario}")
        return valor

    def receber_pix(self, valor: Decimal, remetente: str) -> None:
        self.saldo += valor
        self._registrar("Pix recebido", valor, f"De {remetente}")

    # ---------------- cofrinho ----------------
    def guardar(self, valor) -> None:
        valor = valor_positivo(valor)
        self._debitar(valor)
        self.cofrinho += valor
        self._registrar("Guardar no cofrinho", -valor)

    def resgatar(self, valor) -> None:
        valor = valor_positivo(valor)
        if valor > self.cofrinho:
            raise SaldoInsuficienteErro(f"Cofrinho tem apenas {formatar(self.cofrinho)}.")
        self.cofrinho -= valor
        self.saldo += valor
        self._registrar("Resgate do cofrinho", valor)

    def render_cofrinho(self, taxa: Decimal = Decimal("0.005")) -> Decimal:
        juros = (self.cofrinho * taxa).quantize(Decimal("0.01"), ROUND_HALF_UP)
        self.cofrinho += juros
        return juros

    # ---------------- cartões ----------------
    def emitir_cartao(self, bandeira: str = "Master", limite=1000) -> Cartao:
        limite = valor_positivo(limite)
        final = f"{random.randint(0, 9999):04d}"
        cartao = Cartao(final, bandeira, limite)
        self.cartoes.append(cartao)
        return cartao

    def _cartao(self, final: str) -> Cartao:
        for c in self.cartoes:
            if c.final == final:
                return c
        raise CartaoErro("Cartão não encontrado.")

    def bloquear_cartao(self, final: str, bloquear: bool = True) -> None:
        self._cartao(final).bloqueado = bloquear

    def comprar_no_credito(self, final: str, valor) -> None:
        cartao, valor = self._cartao(final), valor_positivo(valor)
        if cartao.bloqueado:
            raise CartaoErro("Cartão bloqueado.")
        if valor > cartao.disponivel:
            raise CartaoErro(f"Limite insuficiente. Disponível: {formatar(cartao.disponivel)}")
        cartao.fatura += valor

    def pagar_fatura(self, final: str, valor=None) -> Decimal:
        cartao = self._cartao(final)
        valor = cartao.fatura if valor is None else valor_positivo(valor)
        if valor <= 0 or valor > cartao.fatura:
            raise ValorInvalidoErro(f"Valor inválido. Fatura atual: {formatar(cartao.fatura)}")
        self._debitar(valor)
        cartao.fatura -= valor
        self._registrar("Pagamento de fatura", -valor, f"Cartão final {final}")
        return valor

    # ---------------- pagamentos ----------------
    def pagar_boleto(self, codigo: str, valor) -> Transacao:
        codigo = "".join(ch for ch in codigo if ch.isdigit())
        if len(codigo) not in (47, 48):
            raise ValorInvalidoErro("Código de barras inválido (deve ter 47 ou 48 dígitos).")
        valor = valor_positivo(valor)
        self._debitar(valor)
        return self._registrar("Pagamento de boleto", -valor, f"Código ...{codigo[-6:]}")


    def resumo(self) -> dict:
        return {
            "titular": self.titular,
            "numero": self.numero,
            "saldo": self.saldo,
            "cofrinho": self.cofrinho,
            "chaves_pix": dict(self.chaves_pix),
            "qtd_cartoes": len(self.cartoes),
            "ultimas_transacoes": self.extrato(5),
        }


    def to_dict(self) -> dict:
        return json.loads(json.dumps(asdict(self), default=str))  # Decimal -> str

    @classmethod
    def from_dict(cls, d: dict) -> "Conta":
        d = dict(d)
        for campo in ("saldo", "cofrinho", "limite_pix_diario"):
            d[campo] = Decimal(d[campo])
        d["cartoes"] = [
            Cartao(**{**c, "limite": Decimal(c["limite"]), "fatura": Decimal(c["fatura"])})
            for c in d["cartoes"]
        ]
        d["transacoes"] = [
            Transacao(**{**t, "valor": Decimal(t["valor"]), "saldo_apos": Decimal(t["saldo_apos"])})
            for t in d["transacoes"]
        ]
        return cls(**d)



class Banco:
    MAX_TENTATIVAS = 3

    def __init__(self, arquivo: str = "banco_dados.json"):
        self.arquivo = Path(arquivo)
        self.contas: dict[str, Conta] = {}
        self.carregar()

    def cadastrar(self, titular: str, usuario: str, senha: str) -> Conta:
        usuario = usuario.strip().lower()
        if not titular.strip() or not usuario:
            raise AutenticacaoErro("Nome e usuário são obrigatórios.")
        if usuario in self.contas:
            raise AutenticacaoErro("Esse usuário já existe.")
        if len(senha) < 6:
            raise AutenticacaoErro("A senha deve ter pelo menos 6 caracteres.")
        salt, h = _hash_senha(senha)
        numero = f"{random.randint(0, 99999999):08d}"
        conta = Conta(titular.strip(), usuario, salt, h, numero)
        self.contas[usuario] = conta
        self.salvar()
        return conta

    def login(self, usuario: str, senha: str) -> Conta:
        conta = self.contas.get(usuario.strip().lower())
        if conta is None:
            raise AutenticacaoErro("Usuário ou senha incorretos.")
        if conta.bloqueada:
            raise AutenticacaoErro("Conta bloqueada por excesso de tentativas.")
        if not conta.verificar_senha(senha):
            conta.tentativas_falhas += 1
            if conta.tentativas_falhas >= self.MAX_TENTATIVAS:
                conta.bloqueada = True
            self.salvar()
            raise AutenticacaoErro("Usuário ou senha incorretos.")
        conta.tentativas_falhas = 0
        self.salvar()
        return conta

    def desbloquear_conta(self, usuario: str) -> None:
        conta = self.contas[usuario]
        conta.bloqueada, conta.tentativas_falhas = False, 0
        self.salvar()

    def buscar_por_chave(self, chave: str) -> Conta | None:
        chave = chave.strip().lower()
        for conta in self.contas.values():
            if chave in conta.chaves_pix.values():
                return conta
        return None

    def fazer_pix(self, origem: Conta, chave: str, valor) -> Decimal:
        destino = self.buscar_por_chave(chave)
        if destino is None:
            raise ChavePixErro("Chave Pix não encontrada.")
        if destino is origem:
            raise ChavePixErro("Você não pode enviar Pix para si mesmo.")
        valor = origem.debitar_pix(valor, destino.titular)
        destino.receber_pix(valor, origem.titular)
        self.salvar()
        return valor


    def salvar(self) -> None:
        dados = {u: c.to_dict() for u, c in self.contas.items()}
        self.arquivo.write_text(json.dumps(dados, indent=2, ensure_ascii=False), encoding="utf-8")

    def carregar(self) -> None:
        if self.arquivo.exists():
            dados = json.loads(self.arquivo.read_text(encoding="utf-8"))
            self.contas = {u: Conta.from_dict(c) for u, c in dados.items()}



LINHA = "-" * 44


def ler(msg: str) -> str:
    return input(msg).strip()


def mostrar_extrato(conta: Conta) -> None:
    print("\n--------- EXTRATO ---------")
    transacoes = conta.extrato(15)
    if not transacoes:
        print("Nenhuma movimentação.")
    for t in transacoes:
        sinal = "+" if t.valor > 0 else "-"
        print(f"{t.data.replace('T', ' ')} | {t.tipo:<20} | {sinal} {formatar(abs(t.valor)):>14} | {t.descricao}")
    print(f"\nSaldo atual: {formatar(conta.saldo)}")


def menu_cartoes(conta: Conta) -> None:
    print("\n1. Listar  2. Emitir novo  3. Bloquear/Desbloquear  4. Compra no crédito  5. Pagar fatura")
    op = ler("Opção: ")
    if op == "1":
        if not conta.cartoes:
            print("Nenhum cartão cadastrado.")
        for c in conta.cartoes:
            estado = "BLOQUEADO" if c.bloqueado else "ativo"
            print(f"{c.bandeira} final {c.final} | limite {formatar(c.limite)} | fatura {formatar(c.fatura)} | {estado}")
    elif op == "2":
        c = conta.emitir_cartao("Master", ler("Limite desejado: "))
        print(f"Cartão emitido! Final {c.final}")
    elif op == "3":
        final = ler("Final do cartão: ")
        cartao = conta._cartao(final)
        conta.bloquear_cartao(final, not cartao.bloqueado)
        print("Cartão", "desbloqueado." if cartao.bloqueado is False else "bloqueado.")
    elif op == "4":
        conta.comprar_no_credito(ler("Final do cartão: "), ler("Valor da compra: "))
        print("Compra aprovada!")
    elif op == "5":
        pago = conta.pagar_fatura(ler("Final do cartão: "))
        print(f"Fatura paga: {formatar(pago)}")


def menu_cofrinho(conta: Conta) -> None:
    print(f"\nCofrinho: {formatar(conta.cofrinho)}")
    print("1. Guardar  2. Resgatar  3. Simular rendimento (0,5%)")
    op = ler("Opção: ")
    if op == "1":
        conta.guardar(ler("Valor: "))
        print("Valor guardado!")
    elif op == "2":
        conta.resgatar(ler("Valor: "))
        print("Valor resgatado!")
    elif op == "3":
        print(f"Rendimento aplicado: {formatar(conta.render_cofrinho())}")


def menu_config(conta: Conta) -> None:
    print("\n1. Minhas chaves Pix  2. Cadastrar chave Pix  3. Remover chave Pix  4. Trocar senha")
    op = ler("Opção: ")
    if op == "1":
        print(conta.chaves_pix or "Nenhuma chave cadastrada.")
    elif op == "2":
        tipo = ler("Tipo (cpf/email/telefone/aleatoria): ")
        valor = None if tipo.lower() == "aleatoria" else ler("Valor da chave: ")
        print("Chave cadastrada:", conta.registrar_chave_pix(tipo, valor))
    elif op == "3":
        conta.remover_chave_pix(ler("Tipo da chave a remover: "))
        print("Chave removida.")
    elif op == "4":
        conta.trocar_senha(ler("Senha atual: "), ler("Nova senha: "))
        print("Senha alterada!")


def tela_login(banco: Banco) -> Conta:
    while True:
        print("\n1. Entrar  2. Criar conta")
        op = ler("Opção: ")
        try:
            if op == "1":
                conta = banco.login(ler("Usuário: "), ler("Senha: "))
                print(f"\nBem-vindo(a), {conta.titular}!")
                return conta
            elif op == "2":
                conta = banco.cadastrar(ler("Nome completo: "), ler("Usuário: "), ler("Senha (mín. 6): "))
                print(f"Conta criada! Número: {conta.numero}")
        except BancoErro as e:
            print(f"⚠ {e}")


OPCOES_VALIDAS = {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"}


def menu_principal(banco: Banco, conta: Conta) -> None:
    while True:
        print(f"\n{LINHA}\nOlá, {conta.titular} | Saldo: {formatar(conta.saldo)}\n{LINHA}")
        print("1. Sacar        2. Depositar     3. Fazer Pix")
        print("4. Cartões      5. Pagar boleto  6. Saldo")
        print("7. Extrato      8. Cofrinho      9. Configurações")
        print("0. Sair")
        op = ler("Número do serviço: ")

        if op not in OPCOES_VALIDAS:
            print("")
            print("")
            print("Digite um valor válido!")
            print("")
            print("")
            continue

        try:
            if op == "1":
                t = conta.sacar(ler("Valor do saque: "))
                print(f"DINHEIRO SACADO: {formatar(-t.valor)}")
            elif op == "2":
                t = conta.depositar(ler("Valor do depósito: "))
                print(f"DINHEIRO DEPOSITADO: {formatar(t.valor)}")
            elif op == "3":
                v = banco.fazer_pix(conta, ler("Chave Pix: "), ler("Valor: "))
                print(f"PIX DE {formatar(v)} ENVIADO COM SUCESSO!")
            elif op == "4":
                menu_cartoes(conta)
            elif op == "5":
                conta.pagar_boleto(ler("Código de barras: "), ler("Valor: "))
                print("BOLETO PAGO!")
            elif op == "6":
                print(f"SALDO ATUAL: {formatar(conta.saldo)}")
            elif op == "7":
                mostrar_extrato(conta)
            elif op == "8":
                menu_cofrinho(conta)
            elif op == "9":
                menu_config(conta)
            elif op == "0":
                print("Até logo!")
                return
        except BancoErro as e:
            print(f"⚠ {e}")

        banco.salvar()


def criar_dados_demo(banco: Banco) -> None:
    if banco.contas:
        return
    lucas = banco.cadastrar("Lucas", "lucas@gmail", "lucas123")
    lucas.depositar(1000)
    lucas.registrar_chave_pix("email", "lucas@gmail")
    maria = banco.cadastrar("Maria", "maria@gmail", "maria123")
    maria.depositar(500)
    maria.registrar_chave_pix("email", "maria@gmail.com")
    banco.salvar()


if __name__ == "__main__":
    banco = Banco()
    criar_dados_demo(banco)
    print("=============== BANCO ===============")
    conta_logada = tela_login(banco)
    menu_principal(banco, conta_logada)