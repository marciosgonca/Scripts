import argparse
from ldap3 import Server, Connection, ALL, NTLM

def criar_usuario_ad(servidor, dominio, usuario_admin, senha_admin, ou, nome, sobrenome, usuario, senha):
    cn = f"{nome} {sobrenome}"
    sAMAccountName = usuario
    user_principal_name = f"{usuario}@{dominio}"

    server = Server(servidor, get_info=ALL)
    conn = Connection(
        server,
        user=f"{dominio}\\{usuario_admin}",
        password=senha_admin,
        authentication=NTLM
    )

    if not conn.bind():
        print("❌ Erro ao conectar no AD:", conn.result)
        return

    print("✔ Conectado ao AD")

    user_dn = f"CN={cn},{ou}"

    attributes = {
        "objectClass": ["top", "person", "organizationalPerson", "user"],
        "cn": cn,
        "givenName": nome,
        "sn": sobrenome,
        "displayName": cn,
        "sAMAccountName": sAMAccountName,
        "userPrincipalName": user_principal_name,
    }

    conn.add(user_dn, attributes=attributes)

    if conn.result["result"] == 0:
        print("✔ Usuário criado:", cn)
        conn.extend.microsoft.modify_password(user_dn, senha)
        conn.modify(user_dn, {"userAccountControl": [(conn.MODIFY_REPLACE, [512])]})
        print("✔ Senha definida e conta ativada")
    else:
        print("❌ Erro ao criar usuário:", conn.result)

    conn.unbind()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Criar usuário no Active Directory")

    parser.add_argument("--servidor", required=True, help="Servidor LDAP, ex: ldap://dc01.empresa.local")
    parser.add_argument("--dominio", required=True, help="Domínio, ex: EMPRESA")
    parser.add_argument("--usuario_admin", required=True, help="Usuário com permissão no AD")
    parser.add_argument("--senha_admin", required=True, help="Senha do usuário administrador")
    parser.add_argument("--ou", required=True, help="OU destino, ex: OU=Usuarios,DC=empresa,DC=local")
    parser.add_argument("--nome", required=True, help="Nome do usuário")
    parser.add_argument("--sobrenome", required=True, help="Sobrenome do usuário")
    parser.add_argument("--usuario", required=True, help="sAMAccountName do usuário")
    parser.add_argument("--senha", required=True, help="Senha inicial do usuário")

    args = parser.parse_args()

    criar_usuario_ad(
        args.servidor,
        args.dominio,
        args.usuario_admin,
        args.senha_admin,
        args.ou,
        args.nome,
        args.sobrenome,
        args.usuario,
        args.senha
    )
