# Apple DNS Profile Generator

A web-based tool to generate Apple configuration profiles for encrypted DNS (DNS over HTTPS and DNS over TLS). Enable system-wide encrypted DNS on your iPhone, iPad, Mac, and Apple TV.

## Features

- 🔒 **Encrypted DNS** - Generate profiles for DoH (DNS over HTTPS) and DoT (DNS over TLS)
- 🎯 **Popular Providers** - Pre-configured templates for Cloudflare, Google, Quad9, and AdGuard
- ✏️ **Custom DNS** - Create profiles with your own DNS server configuration
- 📝 **S/MIME Signing** - Optionally sign profiles with your own certificate
- 🔐 **Privacy First** - All generation happens locally in your browser, no data sent to servers
- 📱 **Multi-Platform** - Works on iOS, iPadOS, macOS, and tvOS

## How to Use

1. **Select a DNS Provider** - Choose from popular providers or enter custom DNS settings
2. **Choose Protocol** - Select DNS over HTTPS (DoH) or DNS over TLS (DoT)
3. **Configure Options** - Set profile name, description, and optional Wi-Fi/cellular restrictions
4. **Optional Signing** - Add your signing certificate and private key for S/MIME signing
5. **Download** - Click "Download Profile" to get your `.mobileconfig` file

## Installation

### iOS / iPadOS
1. Download the configuration profile
2. Open the Settings app
3. Tap "Profile Downloaded"
4. Tap Install and follow the onscreen instructions

### macOS
1. Download the configuration profile
2. Open the downloaded `.mobileconfig` file
3. Open System Preferences → Profiles
4. Click Install

### tvOS
1. Open Settings → General → Privacy
2. Hover over "Share Apple TV Analytics" without pressing
3. Press Play on the remote
4. Select "Add Profile" and enter the profile URL

## Compatibility

- **iOS / iPadOS**: 14.0 and later
- **macOS**: 11.0 (Big Sur) and later
- **tvOS**: 14.0 and later

## Development

This project is built with:

- [React](https://react.dev/) + [TypeScript](https://www.typescriptlang.org/)
- [Vite](https://vitejs.dev/)
- [Tailwind CSS](https://tailwindcss.com/)
- [shadcn/ui](https://ui.shadcn.com/)
- [PKI.js](https://pkijs.org/) for S/MIME signing

### Getting Started

```bash
# Clone the repository
git clone https://github.com/fransallen/apple-dns.git

# Navigate to the project directory
cd apple-dns

# Install dependencies
npm install

# Start the development server
npm run dev
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is open source and available under the [MIT License](LICENSE).

## Resources

- [Apple DNS Settings Documentation](https://developer.apple.com/documentation/devicemanagement/dnssettings)
- [Encrypted DNS Overview](https://support.apple.com/guide/deployment/encrypted-dns-depf7c8d4e3c/web)
