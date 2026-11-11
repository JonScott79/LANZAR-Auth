import { QRCodeSVG } from 'qrcode.react'

/**
 * Renders a scannable TOTP provisioning URI locally in the browser as crisp SVG.
 * Never transmits the provisioning URI or secret to any external service.
 */
export default function TotpQrCode({ otpauthUrl, size = 184 }) {
  if (!otpauthUrl || typeof otpauthUrl !== 'string' || !otpauthUrl.startsWith('otpauth://')) {
    return null
  }

  return (
    <div
      className="qr-code-frame"
      role="img"
      aria-label="Authenticator QR Code"
    >
      <QRCodeSVG
        value={otpauthUrl}
        size={size}
        level="M"
        bgColor="#ffffff"
        fgColor="#000000"
        includeMargin
      />
    </div>
  )
}
