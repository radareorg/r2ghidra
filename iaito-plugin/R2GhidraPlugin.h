/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#ifndef R2GHIDRAPLUGIN_H
#define R2GHIDRAPLUGIN_H

#include <QObject>
#include <QtPlugin>
#include <plugins/IaitoPlugin.h>

class R2GhidraPlugin : public QObject, IaitoPlugin
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID "org.radare.iaito.plugins.r2ghidra")
    Q_INTERFACES(IaitoPlugin)

public:
    void setupPlugin() override;
    void setupInterface(MainWindow *main) override;
    void registerDecompilers() override;

    QString getName() const          { return "Ghidra Decompiler (r2ghidra)"; }
    QString getAuthor() const        { return "thestr4ng3r"; }
    QString getDescription() const   { return "GUI Integration of r2ghidra."; }
    QString getVersion() const       { return "1.0"; }
};


#endif // IAITOSAMPLEPLUGIN_H
