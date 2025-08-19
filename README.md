# PacketFilterVisualizer

An interactive Flask web application for visualizing and benchmarking packet filtering algorithms (Skip List vs Splay Tree) on ACL2 and IPC2 datasets. Includes dynamic dataset selection and interactive Plotly graphs.

---

## 🚀 Features

- **Interactive Web Dashboard:** Select dataset and graph type from a modern, dark-themed UI.
- **Algorithm Comparison:** Visualize and compare Skip List vs Splay Tree filtering performance.
- **Dynamic Dataset Selection:** Switch between ACL2 and IPC2 datasets instantly.
- **Interactive Graphs:** Zoom, pan, and hover for tooltips using Plotly.
- **Clean Code Structure:** Modular Python code for easy extension.

---

## 🛠️ Technologies Used

- Python 3
- Flask
- Plotly
- Matplotlib (optional, for static plots)
- Custom packet filtering algorithms (Skip List, Splay Tree)

---

## 📂 Datasets

- **ACL2:** Located in `Data_set/acl2/acl2_8k/`
- **IPC2:** Located in `Data_set/ip2/ipc2_8k/`

> **Note:** Datasets are not included for copyright reasons.  
> Place your datasets in the specified folders for the app to work.

---

## ⚡ Getting Started

1. **Clone the repository:**
    ```bash
    git clone https://github.com/yourusername/PacketFilterVisualizer.git
    cd PacketFilterVisualizer
    ```

2. **Install dependencies:**
    ```bash
    pip install flask plotly
    ```

3. **Add your datasets:**
    - Place ACL2 and IPC2 datasets in the correct folders as described above.

4. **Run the app:**
    ```bash
    python webapp.py
    ```
    - Open your browser at [http://127.0.0.1:5000](http://127.0.0.1:5000)

---

## 📈 How It Works

- Select a dataset (ACL2 or IPC2) and a graph type (Protocol Search or IP Packet Search).
- The app benchmarks packet filtering using Skip List and Splay Tree algorithms.
- Results are displayed as interactive graphs for easy comparison.

---

## 📝 Future Improvements

- Allow users to upload custom datasets.
- Add more filtering algorithms for comparison.
- Download filtered results and graphs.
- Add summary statistics and data tables.

---

## 📄 License

MIT License

---
---
