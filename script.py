from p2python.crypto.id_generator import IDGenerator


def main():
    gen = IDGenerator()
    gen.add_public_key("0xc0fffe254729295a45a2885639AC7E10F9d5497945a3875639AC7E10F9d54989")
    gen.add_ip_address("104.218.67.207")
    gen.add_port(65536)
    id = gen.generate_id()
    print(id)

if __name__ == "__main__":
    main()