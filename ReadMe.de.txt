======================================================================
                sha256 - SHA-256-Prüfsummen berechnen
                           (von Thoronador)
======================================================================


Zweck des Programmes:
=====================

Das Programm sha256 soll dazu dienen, SHA-256-Prüfsummen (256bit) zu
allen Dateien, die dem Programm als Befehlszeilenparameter übergeben
werden, zu berechnen und auszugeben.
Seit Version 1.1 kann man alternativ auch SHA-1-Prüfsummen (160bit)
berechnen lassen, falls dies gewünscht wird.


Programmaufruf:
===============

Da dies (offensichtlich) ein Kommandozeilenprogramm ist, kann man es
via Kommandozeile/ Shell aufrufen. Eine Liste der erlaubten Parameter
folgt.


Übersicht:
----------

  sha256 [--sha1 | --sha256] DATEINAME ...


Optionen + Parameter:
---------------------

  --sha1
      Berechnet SHA-1-Prüfsummen (160bit) anstelle von SHA-256.

  --sha256
      Berechnet SHA-256-Prüfsummen (256bit). Dies ist die Standard-
      vorgabe.

  --help
      Zeigt einen (englischen) Hilfetext und listet gültige Programm-
      optionen auf.

  --version
      Gibt Versionsinformationen aus und beendet das Programm.

  DATEINAME
        Pfad zu einer Datei, deren Prüfsumme berechnet werden soll.
        Kann mehrmals angegeben werden, um mehrere Dateien auszu-
        werten.

Ein typischer Aufruf kann so aussehen:

  sha256 foo.txt some_dir/bar.baz

Damit würden die SHA-256-Prüfsummen von foo.txt und bar.baz im Unter-
verzeichnis some_dir berechnet (und ausgegeben) werden. Falls eine der
angegebenen Dateien nicht existiert, bricht das Programm ab.


Lizenz und Quellcode
====================

Das Programm sha256 steht unter der GNU General Public Licence 3,
einer freien Softwarelizenz. Der volle Text der Lizenz ist in der
Datei GPL.txt enthalten und kann auch auf
  http://www.gnu.org/licenses/gpl-3.0.html
eingesehen werden.

Das Programm wurde in der Hoffnung, dass es nützlich ist, erstellt
und verfügbar gemacht. Das Programm ist nicht vollendet und kann daher
Fehler ("Bugs") enthalten. Aus den genannten Gründen wird es unter
dieser Lizenz „so wie es ist“ ohne jegliche Gewährleistung zur Verfü-
gung gestellt. Dies gilt unter anderem - aber nicht ausschließlich -
für Verwendbarkeit für einen bestimmten Zweck, Mängelfreiheit und
Richtigkeit (siehe dazu die entsprechenden Abschnitte der GNU General
Public Licence 3).

Der Quellcode des Programms lässt sich auf Sourceforge.net einsehen,
das Projekt findet sich unter
  http://sourceforge.net/projects/random-thoro/
