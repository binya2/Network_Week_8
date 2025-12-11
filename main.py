from core.utils import (
    str_generator,
    analysis_ip,
    writing_to_file,
    validate_mask,
    validate_ip,
)


STUDENT_ID = "209700798"


def exam_file() -> None:
    ip_addresses = {
        "a": {"ip": "192.168.10.130", "Mask": "255.255.255.192"},
        "b": {"ip": "172.16.45.200", "Mask": "255.255.240.0"},
        "c": {"ip": "10.50.200.7", "Mask": "255.240.0.0"},
    }

    for key in ip_addresses:
        ip = ip_addresses[key]["ip"]
        mask = ip_addresses[key]["Mask"]
        class_type, network, broadcast, num_hosts, cidr_mask = analysis_ip(ip, mask)
        str_to_file = str_generator(
            ip, mask, class_type, network, broadcast, num_hosts, cidr_mask
        )
        filename = f"subnet_info_{ip}_{STUDENT_ID}.txt"
        writing_to_file(filename, str_to_file)


def user_interface() -> None:
    while True:
        ip = input("Enter IP address: ").strip()
        mask = input("Enter subnet mask: ").strip()

        if not validate_ip(ip):
            print("Invalid IP address")
            continue

        if not validate_mask(mask):
            print("Invalid subnet mask")
            continue

        break

    class_type, network, broadcast, num_hosts, cidr_mask = analysis_ip(ip, mask)
    str_to_file = str_generator(
        ip, mask, class_type, network, broadcast, num_hosts, cidr_mask
    )
    print(str_to_file)
    filename = f"subnet_info_{ip}_{STUDENT_ID}.txt"
    writing_to_file(filename, str_to_file)
    print(f"Output written to {filename}")


if __name__ == "__main__":
    exam_file()
    # user_interface()
