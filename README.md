# Forensic 3D Watermarking Suite

**Version 1.0** | Advanced spectral watermarking for 3D models with mathematical proof of ownership

[![Python 3.13+](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PyQt5](https://img.shields.io/badge/GUI-PyQt5-green.svg)](https://pypi.org/project/PyQt5/)

---

## Overview

The **Forensic 3D Watermarking Suite** is a tool for embedding invisible, mathematically verifiable watermarks into 3D models (.obj format). Designed for archaeologists and researchers who need to protect their intellectual property, this system provides **forensic-level proof of ownership** that survives geometric transformations, re-exports, and malicious tampering.

Unlike traditional metadata-based protection (which is trivially removed), this watermark is embedded directly into the **geometry itself** using spectral graph theory, making it virtually impossible to remove without destroying the model.

### Key Features

- **Invisible Watermarking** — Imperceptible geometric displacement (< 0.1% of edge length)
- **Cryptographically Secure** — Secret key + encrypted master deed (.dna.npz keyfile)
- **Robust Detection** — Survives scaling, rotation, stretching, vertex reordering, and decimation
- **Mathematical Proof** — Correlation-based verification (15-99%+ = confirmed ownership)
- **GUI** — Drag-and-drop interface with real-time logs and debug tools
- **High Performance** — Handles meshes from 100 to 100,000+ vertices
- **Forensic Grade** — ICP alignment + matched-filter extraction for maximum accuracy

---

## Quick Start

### Prerequisites

- **Python 3.13+** ([Download](https://www.python.org/downloads/))
- **Windows** (tested on Windows 10)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/archtecgr/Forensic_3D_Watermarking_Suite.git
   cd Forensic_3D_Watermarking_Suite
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**
   ```bash
   python main.py
   ```

### Standalone Executable (Windows)

Download the pre-built `.exe` from [Releases](https://github.com/archtecgr/Forensic-3D-Watermarking-with-Spectral-Analysis/releases) — no Python installation required.

---

## Usage Guide

### 1. Protecting a Model (Embedding Watermark)

1. **Open the Protect Tab**
2. **Load your .obj model** — Drag & drop or click to browse
3. **Enter a Secret Key** — Unique identifier (e.g., "MyStudio2024")
4. **Set Keyfile Password** — Strong password to encrypt the master deed
5. **Configure Parameters** (optional):
   - **Spectral Modes**: 20 (default, max security)
   - **Safety Divisor**: 50 (default, max security — lower = stronger signal)
6. **Click "Inject Digital DNA"**

**Output:**
- `yourmodel_watermarked.obj` — Protected model (distribute this)
- `yourmodel.dna.npz` — Master deed (keep secret & safe!)

### 2. Verifying Ownership (Auditing)

1. **Open the Audit Tab**
2. **Load Suspect Model** — The model you want to check
3. **Load Master Deed** — Your .dna.npz keyfile
4. **Enter Keyfile Password**
5. **Click "Run Forensic Audit"**

**Results:**
- **OWNERSHIP CONFIRMED (>15%)** — Watermark detected
- **NO MATCH (<15%)** — No watermark or different source
- **Correlation %** — Higher = stronger proof (90%+ = perfect)
- **ICP Error** — Shape match quality (<0.05 = same mesh)

---

## Technical Details

### Watermarking Algorithm

The system uses **spectral graph watermarking** based on Laplacian eigenvector decomposition:

1. **Spectral Decomposition** — Compute the cotangent Laplacian matrix and extract the k smallest non-zero eigenvectors (smooth, low-frequency basis functions)
2. **Payload Generation** — Derive a deterministic payload vector from the secret key via SHA-256 hashing + unit normalization
3. **Embedding** — Project the payload onto the eigenbasis: `displacement = eigenvectors @ payload`
4. **Geometric Injection** — Displace vertices along surface normals by scaled displacement magnitudes
5. **Keyfile Storage** — Encrypt and store original mesh, eigenvectors, payload, and metadata in `.dna.npz`

### Extraction & Verification

1. **Normalisation** — Adaptive PCA-based normalisation undoes non-uniform scaling/stretching
2. **ICP Alignment** — Align suspect mesh to stored original using Iterative Closest Point
3. **Correspondence Recovery** — KD-tree nearest-neighbor to handle vertex reordering (Blender exports)
4. **Matched Filtering** — Project displacement onto stored eigenvectors: `recovered = eigenvectors.T @ displacement`
5. **Correlation** — Compute Pearson correlation between recovered and stored payloads

### Robustness

The watermark survives:
- ✅ **Uniform scaling** (0.01x to 1000x)
- ✅ **Non-uniform stretching** (3x on one axis, 0.1x on another)
- ✅ **Rotation** (any angle)
- ✅ **Translation** (any position)
- ✅ **Vertex reordering** (Blender, Maya, 3ds Max exports)
- ✅ **Precision truncation** (6 decimal places)
- ✅ **Mesh decimation** (30-70% vertex reduction)
- ✅ **Subdivision** (Catmull-Clark, Loop)
- ⚠️ **Remeshing** (partial — depends on topology preservation)
- ❌ **Extreme noise** (>10% of edge length destroys geometry)

---

## Performance

| Mesh Size | Protection Time | Audit Time |
|-----------|----------------|------------|
| 500 verts | 0.3s | 0.2s |
| 5,000 verts | 1.2s | 0.8s |
| 50,000 verts | 8.5s | 4.1s |
| 500,000 verts | ~90s | ~45s |

*Tested on AMD Ryzen 9 5900X, 32GB RAM*

---

## Building from Source

### Create Standalone Executable

```bash
# Install PyInstaller
pip install pyinstaller

# Build .exe (Windows)
pyinstaller --onefile --windowed --name "Forensic3DWatermark" main.py

# Output: dist/Forensic3DWatermark.exe
```

### Run Tests

```bash
python -m pytest tests/
```

---

## Project Structure

```
Forensic_3D_Watermarking_Suite/
├── main.py                    # GUI application entry point
├── spectral_engine.py         # Watermark embedding & extraction
├── icp_alignment.py           # ICP + adaptive normalization
├── forensic_audit.py          # Verification pipeline
├── dna_keyfile.py             # Keyfile encryption/decryption
├── mesh_io.py                 # OBJ file parser
├── generate_test_mesh.py      # Test mesh generators
├── requirements.txt           # Python dependencies
├── README.md                  # This file
└── tests/                     # Unit tests
    ├── test_spectral.py
    ├── test_icp.py
    └── test_audit.py
```

---

## Example Results

### Self-Audit (Perfect Match)
```
Suspect: suitcase_watermarked.obj
Keyfile: suitcase.dna.npz
Result: OWNERSHIP CONFIRMED (99.68%)
ICP Error: 0.0007
```

### Stretched Model (5x stretch on X-axis)
```
Suspect: suitcase_stretched_5x.obj
Keyfile: suitcase.dna.npz
Result: OWNERSHIP CONFIRMED (96.2%)
ICP Error: 0.0005
```

### Wrong Keyfile (Cross-Check)
```
Suspect: sphere_watermarked.obj
Keyfile: torus.dna.npz
Result: NO MATCH (-14.2%)
ICP Error: 0.1727 (shape mismatch)
```

---

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Development Setup

```bash
# Clone your fork
git clone https://github.com/yourusername/Forensic_3D_Watermarking_Suite.git

# Install dev dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/ -v

# Check code style
flake8 *.py
```

---

## License

This project is licensed under the **MIT License**.

---

## Acknowledgments

- **Spectral Graph Theory** — Foundation from *Spectral Graph Theory* by Fan Chung
- **Laplacian Mesh Processing** — Techniques from SIGGRAPH papers on mesh smoothing
- **ICP Algorithm** — Based on Besl & McKay's original 1992 paper
- **PyQt5 Framework** — Riverbank Computing Ltd.
- **NumPy & SciPy** — Scientific Python community

---

## Contact

**Orfeas Dialinos**
- GitHub: [@archtecgr](https://github.com/archtecgr)
- Email: [orfeasdialinos2024@gmail.com](mailto:orfeasdialinos2024@gmail.com)

---

## 🔮 Future Roadmap

- [ ] Support for additional formats (.stl, .ply, .fbx)
- [ ] GPU acceleration (CUDA/OpenCL)
- [ ] Batch processing mode
- [ ] Web-based verification portal
- [ ] Mobile app (iOS/Android)
- [ ] Blockchain-based deed registry
- [ ] Advanced attack resistance (noise injection, smoothing)

---

## Disclaimer

This software is provided "as-is" for research and legitimate intellectual property protection purposes. The authors are not responsible for misuse or any legal implications arising from the use of this tool. Always consult with legal counsel regarding intellectual property matters.

---

## Citation

If you use this software in academic research, please cite:

```bibtex
@software{dialinos2024forensic3d,
  author = {Dialinos, Orfeas},
  title = {Forensic 3D Watermarking Suite},
  year = {2026},
  publisher = {GitHub},
  url = {https://github.com/archtecgr/Forensic_3D_Watermarking_Suite}
}
```

---

<div align="center">

**Made with ❤️ by Orfeas Dialinos**

[⬆ Back to Top](#forensic-3d-watermarking-suite)

</div>
