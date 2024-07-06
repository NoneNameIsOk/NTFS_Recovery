from tkinter import *
from tkinter import messagebox, filedialog, ttk
import win32api
from struct import unpack
from NTFS_recover import BPB_info, MFT


def get_drives():
    ori_drives = win32api.GetLogicalDriveStrings()
    split_drive = ori_drives.split("\x00")
    drives = []
    for drive in split_drive:
        if drive:
            drives.append(drive[0] + ":\\")
    return drives


def find_boot_sector(file_path):
    # 扫描 VHD 文件以找到引导扇区
    try:
        with open(file_path, 'rb') as f:
            while True:
                data = f.read(512)
                if len(data) < 512:
                    break
                # NTFS 引导扇区标识符是 "NTFS" 字符串
                if data[3:8] == b'NTFS ':
                    return data
    except Exception as e:
        raise Exception(f"Error finding boot sector: {str(e)}")
    return None


def read_system_info(file_path):
    try:
        boot_sector = find_boot_sector(file_path)
        if not boot_sector:
            return "Error: Boot sector not found."

        oem_id = boot_sector[3:11].decode('ascii', errors='ignore').strip()
        bytes_per_sector = unpack('<H', boot_sector[11:13])[0]
        sectors_per_cluster = boot_sector[13]
        reserved_sectors = unpack('<H', boot_sector[14:16])[0]
        total_sectors = unpack('<I', boot_sector[40:44])[0]  # NTFS 特定字段
        mft_cluster = unpack('<Q', boot_sector[48:56])[0]  # MFT 起始簇
        info = (f"OEM ID: {oem_id}\n"
                f"每扇区字节数: {bytes_per_sector}\n"
                f"每簇扇区数: {sectors_per_cluster}\n"
                f"保留扇区数: {reserved_sectors}\n"
                f"总扇区数: {total_sectors}\n"
                f"MFT起始簇: {mft_cluster}\n")
        return info
    except Exception as e:
        return f"Error reading system info: {str(e)}"


def read_dbr(file_path):
    try:
        boot_sector = find_boot_sector(file_path)
        if not boot_sector:
            return "Error: Boot sector not found."
        return format_hex_output(boot_sector)
    except Exception as e:
        return f"Error reading DBR: {str(e)}"


def read_mbr(file_path):
    try:
        with open(file_path, 'rb') as f:
            f.seek(0)  # MBR位于0扇区
            data = f.read(512)
        return format_hex_output(data)
    except Exception as e:
        return f"Error reading MBR: {str(e)}"


def format_hex_output(data):
    hex_str = data.hex()
    formatted_output = ""
    for i in range(0, len(hex_str), 32):
        segment = hex_str[i:i + 32]
        hex_pairs = " ".join(segment[j:j + 2] for j in range(0, len(segment), 2))
        formatted_output += f"{i // 2:08X}  {hex_pairs}\n"
    return formatted_output


class SCREEN:

    def __init__(self):
        self.recover_mft = None
        self.delete_file = []
        self.root_window = Tk()  # 创建窗口对象的背景色
        self.root_window.geometry('450x300')  # 设置窗口大小
        self.root_window.title("NTFS文件系统-文件恢复")  # 设置title
        self.file_list_box = Listbox(self.root_window)  # 文件列表
        self.select_disk_label = Label(self.root_window, text="盘符选择：", font=('微软雅黑', 15))  # 标签
        self.select_disk_button = Button(self.root_window, text="确定", width=10, command=self.select_disk)
        self.scan_disk_button = Button(self.root_window, text="扫描文件", width=10, command=self.scan_disk)
        self.resume_file_button = Button(self.root_window, text="恢复文件", width=10, command=self.resume_file)
        self.disk_cbox = ttk.Combobox(self.root_window)  # 创建 列表组件
        self.disk_cbox['value'] = get_drives()  # 设置下拉菜单中的值
        self.disk_cbox.current(0)  # 通过 current() 设置下拉菜单选项的默认值
        self.path = StringVar()
        self.path_label = Label(self.root_window, text="选择保存路径:")
        self.path_entry = Entry(self.root_window, textvariable=self.path)
        self.path_button = Button(self.root_window, text="路径选择", command=self.select_path)
        self.disk_info_button = Button(self.root_window, text="磁盘信息", command=self.open_disk_info_dialog)

    def select_disk(self):
        select_disk_value = self.disk_cbox.get()[0]
        # 要恢复的磁盘
        recover_drive = BPB_info(select_disk_value)
        start_position = recover_drive.return_start_position()
        self.recover_mft = MFT(start_position, select_disk_value, recover_drive.sector_per_cluster,
                               recover_drive.bytes_per_sector)

        # 刷新界面组件
        self.select_disk_label.destroy()
        self.disk_cbox.destroy()
        self.select_disk_button.destroy()
        self.path_label.place(relx=0.1, rely=0.1)
        self.path_entry.place(relx=0.3, rely=0.1)
        self.path_button.place(relx=0.7, rely=0.1)
        self.scan_disk_button.place(relx=0.7, rely=0.3)
        self.resume_file_button.place(relx=0.7, rely=0.6)
        self.file_list_box.place(relx=0, rely=0.3, height=300, width=300)

    def scan_disk(self):
        file_list = []
        self.delete_file = self.recover_mft.find_delete_file_list()
        self.file_list_box.delete(0, len(self.delete_file))
        for i in self.delete_file:
            file_list.append(i[2])
        for i in file_list:
            self.file_list_box.insert("end", i)

    def resume_file(self):
        select_index = self.file_list_box.curselection()
        target_path = self.path_entry.get()
        if target_path:
            tuple_file = self.delete_file[select_index[0]]
            self.recover_mft.recover_file(tuple_file[0], tuple_file[1], tuple_file[2], target_path)
            messagebox.showinfo("消息", "恢复文件成功！")
        else:
            messagebox.showinfo("消息", "保存路径不能为空！")

    def select_path(self):
        self.path.set(filedialog.askdirectory())

    def open_disk_info_dialog(self):
        DiskInfoDialog(self.root_window)

    def start(self):
        self.select_disk_label.grid(row=0, column=0, padx=10, pady=15)
        self.disk_cbox.grid(row=1, column=1)
        self.select_disk_button.grid(row=1, column=2, padx=10, pady=5)
        self.disk_info_button.grid(row=2, column=1, pady=10)
        self.root_window.mainloop()


class DiskInfoDialog:

    def __init__(self, root):
        self.root = root
        self.dialog = Toplevel(root)
        self.dialog.title("磁盘信息")
        self.dialog.geometry("500x400")

        self.file_path = StringVar()
        self.create_widgets()

    def create_widgets(self):
        # 文件路径选择
        Label(self.dialog, text="选择磁盘镜像文件:").pack(pady=10)
        Entry(self.dialog, textvariable=self.file_path, width=50).pack(pady=5)
        Button(self.dialog, text="选择文件", command=self.select_file).pack(pady=5)

        # 显示磁盘信息的文本框
        self.info_display = Text(self.dialog, height=15, width=60)
        self.info_display.pack(pady=10)

        # 按钮
        Button(self.dialog, text="读取系统信息", command=self.read_disk_info).pack(pady=5)
        Button(self.dialog, text="读取DBR", command=self.read_dbr).pack(pady=5)
        Button(self.dialog, text="读取MBR", command=self.read_mbr).pack(pady=5)

    def select_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("VHD Files", "*.vhd")])
        self.file_path.set(file_path)

    def read_disk_info(self):
        try:
            file_path = self.file_path.get()
            if not file_path:
                messagebox.showerror("错误", "请先选择磁盘镜像文件！")
                return
            info = read_system_info(file_path)
            self.info_display.delete(1.0, END)
            self.info_display.insert(END, info)
        except Exception as e:
            messagebox.showerror("错误", str(e))

    def read_dbr(self):
        try:
            file_path = self.file_path.get()
            if not file_path:
                messagebox.showerror("错误", "请先选择磁盘镜像文件！")
                return
            dbr_info = read_dbr(file_path)
            self.info_display.delete(1.0, END)
            self.info_display.insert(END, dbr_info)
        except Exception as e:
            messagebox.showerror("错误", str(e))

    def read_mbr(self):
        try:
            file_path = self.file_path.get()
            if not file_path:
                messagebox.showerror("错误", "请先选择磁盘镜像文件！")
                return
            mbr_info = read_mbr(file_path)
            self.info_display.delete(1.0, END)
            self.info_display.insert(END, mbr_info)
        except Exception as e:
            messagebox.showerror("错误", str(e))


if __name__ == "__main__":
    screen = SCREEN()
    screen.start()
