#!/bin/bash
# ==========================================
# NEXUS - Download Free Alternative Fonts
# Télécharge les polices gratuites alternatives
# ==========================================

set -e

FONTS_DIR="static/fonts"
TEMP_DIR="/tmp/nexus-fonts"

echo "📥 Téléchargement des polices alternatives NEXUS..."

# Créer les dossiers
mkdir -p "$FONTS_DIR"
mkdir -p "$TEMP_DIR"

# ==========================================
# 1. SPACE GROTESK (Hero / Titres)
# Alternative à PP Monument Extended
# ==========================================
echo ""
echo "1️⃣  Space Grotesk (Hero / Titres principaux)"
echo "   → Alternative à PP Monument Extended"

# Télécharger depuis Google Fonts
wget -q "https://fonts.google.com/download?family=Space%20Grotesk" -O "$TEMP_DIR/space-grotesk.zip"
unzip -q "$TEMP_DIR/space-grotesk.zip" -d "$TEMP_DIR/space-grotesk"

# Copier les graisses nécessaires
cp "$TEMP_DIR/space-grotesk/static/SpaceGrotesk-Bold.ttf" "$FONTS_DIR/" 2>/dev/null || true
cp "$TEMP_DIR/space-grotesk/SpaceGrotesk"*"Bold.ttf" "$FONTS_DIR/" 2>/dev/null || true

echo "   ✅ Space Grotesk téléchargé"

# ==========================================
# 2. JETBRAINS MONO (Technique / Monospace)
# Alternative à PP Fraktion Mono
# ==========================================
echo ""
echo "2️⃣  JetBrains Mono (Technique / Monospace)"
echo "   → Alternative à PP Fraktion Mono"

wget -q "https://github.com/JetBrains/JetBrainsMono/releases/download/v2.304/JetBrainsMono-2.304.zip" -O "$TEMP_DIR/jetbrains-mono.zip"
unzip -q "$TEMP_DIR/jetbrains-mono.zip" -d "$TEMP_DIR/jetbrains-mono"

# Copier les graisses nécessaires
cp "$TEMP_DIR/jetbrains-mono/fonts/ttf/JetBrainsMono-Regular.ttf" "$FONTS_DIR/" 2>/dev/null || true
cp "$TEMP_DIR/jetbrains-mono/fonts/ttf/JetBrainsMono-Bold.ttf" "$FONTS_DIR/" 2>/dev/null || true

echo "   ✅ JetBrains Mono téléchargé"

# ==========================================
# 3. INTER (Navigation / UI)
# Alternative à PP Fraktion Grotesk
# ==========================================
echo ""
echo "3️⃣  Inter (Navigation / UI)"
echo "   → Alternative à PP Fraktion Grotesk"

wget -q "https://github.com/rsms/inter/releases/download/v4.0/Inter-4.0.zip" -O "$TEMP_DIR/inter.zip"
unzip -q "$TEMP_DIR/inter.zip" -d "$TEMP_DIR/inter"

# Copier les graisses nécessaires
cp "$TEMP_DIR/inter/Inter Desktop/Inter-Regular.otf" "$FONTS_DIR/" 2>/dev/null || true
cp "$TEMP_DIR/inter/Inter Desktop/Inter-SemiBold.otf" "$FONTS_DIR/" 2>/dev/null || true
cp "$TEMP_DIR/inter/Inter Desktop/Inter-Bold.otf" "$FONTS_DIR/" 2>/dev/null || true

echo "   ✅ Inter téléchargé"

# ==========================================
# Nettoyage
# ==========================================
echo ""
echo "🧹 Nettoyage..."
rm -rf "$TEMP_DIR"

# ==========================================
# Conversion en WOFF2 (optionnel)
# ==========================================
echo ""
echo "🔄 Conversion en WOFF2 (optionnel)..."

if command -v woff2_compress &> /dev/null; then
    echo "   Converting TTF/OTF to WOFF2..."
    for font in "$FONTS_DIR"/*.{ttf,otf}; do
        [ -f "$font" ] && woff2_compress "$font"
    done
    echo "   ✅ Conversion terminée"
else
    echo "   ⚠️  woff2_compress non installé, fichiers TTF/OTF conservés"
    echo "   Pour installer: sudo apt install woff2"
fi

# ==========================================
# Résumé
# ==========================================
echo ""
echo "✅ TERMINÉ!"
echo ""
echo "Polices installées dans: $FONTS_DIR/"
ls -lh "$FONTS_DIR"

echo ""
echo "📝 Prochaines étapes:"
echo "   1. Créer les @font-face dans nexus-variables.css"
echo "   2. Mettre à jour les variables de polices"
echo "   3. Tester le site"
echo ""
echo "Voir DOX/NEXUS-TYPOGRAPHY.md pour les instructions complètes"
