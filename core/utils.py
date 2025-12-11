from core.output_string import format_input_ip, format_subnet_mask, format_classful_status, format_network_address, \
    format_broadcast_address, format_num_hosts, format_cidr_mask


def validate_mask(subnet_mask: str) -> bool:
    binary_subnet_mask = bin(convert_str_to_word(subnet_mask))[1:]
    index = binary_subnet_mask[2:].find('0')
    ones_checker = '1' in binary_subnet_mask[index + 1:]

    return ones_checker and validate_ip(subnet_mask)


def validate_ip(ip_address: str) -> bool:
    octets = ip_address.split('.')
    if len(octets) != 4:
        return False
    for octet in octets:
        if 0 > int(octet) or int(octet) > 255:
            return False
    return True


def analysis_ip(ip: str, mask: str)-> tuple:
    ip_address = convert_str_to_word(ip)
    subnet_mask = convert_str_to_word(mask)

    cidr_mask = bin(subnet_mask).count('1')

    network = ip_address & subnet_mask
    broadcast = network | (2 ** (32 - cidr_mask) - 1)
    network = convert_word_to_str(network)
    broadcast = convert_word_to_str(broadcast)

    subnets_num = (2 ** (32 - cidr_mask) - 2)
    class_type = class_ip_checker(ip,mask)


    return class_type, network, broadcast, subnets_num, cidr_mask


def convert_str_to_word(ip_address: str) -> int:
    ip_bytes = ip_address.split('.')
    word = 0
    for ip_byte in ip_bytes:
        word = (word << 8) + int(ip_byte)
    return word


def convert_word_to_str(word: int) -> str:
    return '.'.join(str((word >> (i * 8)) & 0xFF) for i in range(3, -1, -1))


def check_ip_class(ip_address: str) -> tuple:
    first_octet = int(ip_address.split('.')[0])
    if 0 <= first_octet <= 127:
        return "Class A", "225.0.0.0"
    elif 128 <= first_octet <= 191:
        return "Class B", "225.225.0.0"
    elif 192 <= first_octet <= 223:
        return "Class C", "225.225.225.0"
    else:
        return "D/E", ""


def class_ip_checker(ip_address: str, subnet_mask: str) -> str:
    class_type, class_mask = check_ip_class(ip_address)

    if class_mask == subnet_mask:
        return class_type
    else:
        return "Classless"


def writing_to_file(filename:str, data:str):
    with open(filename, 'w') as f:
        f.write(data)


def str_generator(ip_address, subnet_mask, class_type, network, broadcast, subnets_num, cidr_mask):
    data = (f"{format_input_ip(ip_address)}"
            f"{format_subnet_mask(subnet_mask)}"
            f"{format_classful_status(class_type)}"
            f"{format_network_address(network)}"
            f"{format_broadcast_address(broadcast)}"
            f"{format_num_hosts(subnets_num)}"
            f"{format_cidr_mask(cidr_mask)}")
    return data


