# thecybervedi-Steganography-Project 🎉

Welcome to **thecybervedi-Steganography-Project**! 🚀 This is my Capstone Project for the IBM x EduNet Summer Internship 2025, where I, Shashank Trivedi (aka thecybervedi), crafted a cool AES-encrypted steganography tool. 🌟 It hides secret messages in images (like my custom `thecybervedi.png`!) using LSB (Least Significant Bit) technique, secured with AES-256 and XOR encryption. 🔒 Check it out and let's dive into the world of covert communication! 🕵️‍♂️

## ✨ Project Overview
This project encrypts a message (e.g., "thecybervedi’s cipher by Shashank for IBM x EduNet!") with AES and XOR, embeds it into a 300x300 PNG image, and extracts it back flawlessly. 🎨 Built with Python, OpenCV, and pycryptodome, it runs on Google Colab and showcases my cybersecurity skills. 💻 The output? A stego-image that looks normal but hides a secret! 😄

## 📋 Features
- 🔐 AES-256 encryption for top-notch security.
- 🔧 LSB steganography to embed data in pixel LSBs.
- 📥📤 Encode and decode messages with custom keys (`thecybervedi-aes`, `thecybervedi-xor`).
- ✅ Validates extraction with the original message.
- 🌐 Demo-ready with `thecybervedi.png` as the canvas!

## 🚀 Getting Started
1. 📥 Clone the repo: `git clone https://github.com/thecybervedi/thecybervedi-steganography-project.git`
2. 🐍 Install dependencies: `pip install opencv-python pycryptodome`
3. 📂 Upload `thecybervedi.png` to your Colab environment.
4. ▶️ Run the notebook: Open `thecybervedi_stegnography_project (1).ipynb` in Colab and execute all cells.
5. 🎉 Watch the magic happen—encode, save `stego_image.png`, and decode!

## 🛠️ Tech Stack
- **Python** 🐍: Core logic and image processing.
- **OpenCV** 👁️: Image handling wizardry.
- **pycryptodome** 🔐: AES encryption powerhouse.
- **Google Colab** ☁️: Free cloud execution.

## 📸 Screenshots
- **Original Image**: `original_image.png` (before embedding).
- **Stego Image**: `stego_image.png` (after embedding—spot the difference? 😏).
- **Colab Output**: Success message with extracted text!

## 🎯 Future Scope/Plans 🌈
Ready to take this project to the next level? Here’s what’s cooking! 🍳
- **🔧 Full-Fledged Tool**: Build a web app with encode/decode buttons! Users can upload images, input messages/keys, and get stego-images back. 🎨
- **📤📥 User-Friendly I/O**: Let users upload stego-images and keys to decode messages—total flexibility! 🔑
- **🌐 Web App Dream**: Convert it into a shiny web app using React and host it on GitHub Pages for free! 🚀 Deploy with GitHub Actions for auto-updates. ⚙️
- **💾 Advanced Features**: Add support for multiple images, validate key strength, and maybe even add a PWA mode for offline use! 📱
- **🌍 Global Reach**: Integrate a free backend (e.g., Firebase) for user data or leaderboards—let the world join the steganography fun! 🌐
- **🎮 Gamify It**: Turn it into a challenge—hide secrets for others to crack! 🕹️

Let’s make this project a global sensation—stay tuned for updates! 🔥

## 💬 Contribute
Got ideas? Let’s collaborate and make this epic! 🌟
Contact Me @thecybervedi on Instagram 📱📞

Happy coding, ©️thecybervedi! 🎮
