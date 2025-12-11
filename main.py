from core.utils import str_generator, analysis_ip, writing_to_file, validate_mask, validate_ip


def exam_file():
    ip_addresses = {'a': {'ip': "192.168.10.130", 'Mask': "255.255.255.192"},
                    'b': {'ip': "172.16.45.200", 'Mask': "255.255.240.0"},
                    'c': {'ip': "10.50.200.7", 'Mask': "255.240.0.0"}
                    }

    for ip_mask_address in ip_addresses:
        ip = ip_addresses[ip_mask_address]['ip']
        mask = ip_addresses[ip_mask_address]['Mask']

        class_type, network, broadcast, subnets_num, cidr_mask = analysis_ip(ip, mask)
        str_to_file = str_generator(ip, mask, class_type, network, broadcast, subnets_num, cidr_mask)
        filename = f"subnet_info_{ip}_209700798.txt"
        writing_to_file(filename, str_to_file)


def user_interface():
    while True:
        ip = input("Enter IP number: ")
        mask = input("Enter Mask number: ")
        if not (validate_mask(mask) and validate_ip(ip)):
            print("Invalid Mask or IP number")
            continue
        else:
            break
    class_type, network, broadcast, subnets_num, cidr_mask = analysis_ip(ip, mask)
    str_to_file = str_generator(ip, mask, class_type, network, broadcast, subnets_num, cidr_mask)
    print(str_to_file)


if __name__ == "__main__":
    # exam_file()
    user_interface()
