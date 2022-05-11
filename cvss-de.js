/* Copyright (c) 2015-2019, Chandan B.N.
 *
 * Copyright (c) 2019, FIRST.ORG, INC
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
 * following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
 *    following disclaimer in the documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
 *    products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*

CVSSjs Version 0.1 beta

Usage:
    craete an html element with an id for eg.,
    <div id="cvssboard"></div>

    // create a new instance of CVSS calculator:
    var c = new CVSS("cvssboard");

    // create a new instance of CVSS calculator with some event handler callbacks
    var c = new CVSS("cvssboard", {
                onchange: function() {....} //optional
                onsubmit: function() {....} //optional
                }

    // set a vector
    c.set('AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L');

    //get the value
    c.get() returns an object like:

    {
        score: 4.3,
        vector: 'AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L'
    }

*/

var CVSS = function (id, options) {
    this.options = options;
    this.wId = id;
    var e = function (tag) {
        return document.createElement(tag);
    };

    // Base Group
    this.bg = {
        AV: 'Attack Vector',
        AC: 'Attack Complexity',
        PR: 'Privileges Required',
        UI: 'User Interaction',
        S: 'Scope',
        C: 'Confidentiality',
        I: 'Integrity',
        A: 'Availability'
    };

    // Base Metrics
    this.bm = {
        AV: {
            N: {
                l: 'Network',
                d: "<b>Das Schlimmste:</b> Die verwundbare Komponente ist an den Netzwerk-Stack gebunden, und der Kreis der möglichen Angreifer geht über die anderen unten aufgeführten Optionen hinaus, bis hin zum gesamten Internet. Eine solche Schwachstelle wird oft als 'remote ausnutzbar' bezeichnet und kann als ein Angriff betrachtet werden, der auf Protokollebene über einen oder mehrere Netzwerksprünge hinweg ausgenutzt werden kann (z. B. über einen oder mehrere Router)."
            },
            A: {
                l: 'Adjacent',
                d: "<b>Schlimm:</b> Die anfällige Komponente ist an den Netzwerk-Stack gebunden, aber der Angriff ist auf der Protokollebene auf eine logisch benachbarte Topologie beschränkt. Dies kann bedeuten, dass ein Angriff aus demselben gemeinsam genutzten physischen (z. B. Bluetooth oder IEEE 802.11) oder logischen (z. B. lokales IP-Subnetz) Netzwerk oder aus einer sicheren oder anderweitig begrenzten administrativen Domäne (z. B. MPLS, sicheres VPN zu einer administrativen Netzwerkzone) gestartet werden muss. Ein Beispiel für einen Adjacent-Angriff wäre eine ARP- (IPv4) oder Nachbarschaftserkennungsflut (IPv6), die zu einer Dienstverweigerung im lokalen LAN-Segment führt."
            },
            L: {
                l: 'Local',
                d: "<b>Sehr Schlecht:</b> Die verwundbare Komponente ist nicht an den Netzwerk-Stack gebunden und der Weg des Angreifers führt über Lese-/Schreib-/Ausführungsfunktionen. Entweder:<ul><li>Der Angreifer nutzt die Schwachstelle aus, indem er lokal (z. B. über die Tastatur oder die Konsole) oder aus der Ferne (z. B. über SSH) auf das Zielsystem zugreift</li><li>oder der Angreifer verlässt sich auf die Interaktion des Benutzers durch eine andere Person, um die zum Ausnutzen der Schwachstelle erforderlichen Aktionen durchzuführen (z. B. durch den Einsatz von Social-Engineering-Techniken, um einen legitimen Benutzer zum Öffnen eines bösartigen Dokuments zu verleiten).</li></ul>"
            },
            P: {
                l: 'Physical',
                d: "<b>Schlecht:</b> Der Angriff erfordert, dass der Angreifer die verwundbare Komponente physisch berührt oder manipuliert. Die physische Interaktion kann kurz (z. B. bei einem Angriff durch eine böse Magd) oder dauerhaft sein. Ein Beispiel für einen solchen Angriff ist ein Cold-Boot-Angriff, bei dem ein Angreifer Zugriff auf Festplattenverschlüsselungsschlüssel erhält, nachdem er physisch auf das Zielsystem zugegriffen hat. Andere Beispiele sind Peripherieangriffe über FireWire/USB Direct Memory Access (DMA)."
            }
        },
        AC: {
            L: {
                l: 'Low',
                d: "<b>Das Schlimmste:</b> Es gibt keine besonderen Zugangsbedingungen oder mildernde Umstände. Ein Angreifer kann mit wiederholtem Erfolg rechnen, wenn er die verwundbare Komponente angreift."
            },
            H: {
                l: 'High',
                d: "<b>Schlecht:</b> Ein erfolgreicher Angriff hängt von Bedingungen ab, die sich der Kontrolle des Angreifers entziehen. Das heißt, ein erfolgreicher Angriff kann nicht nach Belieben durchgeführt werden, sondern erfordert, dass der Angreifer einen messbaren Aufwand in die Vorbereitung oder Ausführung gegen die verwundbare Komponente investiert, bevor ein erfolgreicher Angriff erwartet werden kann"
            }
        },
        PR: {
            N: {
                l: 'None',
                d: "<b>Das Schlimmste:</b> Der Angreifer ist vor dem Angriff nicht autorisiert und benötigt daher keinen Zugriff auf Einstellungen oder Dateien des verwundbaren Systems, um einen Angriff durchzuführen."
            },
            L: {
                l: 'Low',
                d: "<b>Schlimmm</b> Der Angreifer benötigt Privilegien, die grundlegende Benutzerfunktionen ermöglichen, die normalerweise nur Einstellungen und Dateien im Besitz eines Benutzers beeinflussen können. Alternativ dazu hat ein Angreifer mit niedrigen Rechten die Möglichkeit, nur auf nicht sensible Ressourcen zuzugreifen."
            },
            H: {
                l: 'High',
                d: "<b>Schlecht:</b> Der Angreifer benötigt Privilegien, die eine erhebliche (z. B. administrative) Kontrolle über die verwundbare Komponente ermöglichen und den Zugriff auf komponentenweite Einstellungen und Dateien erlauben."
            }
        },
        UI: {
            N: {
                l: 'None',
                d: "<b>Das Schlimmste:</b> Das anfällige System kann ohne Zutun eines Benutzers ausgenutzt werden."
            },
            R: {
                l: 'Required',
                d: "<b>Schlecht:</b> Für eine erfolgreiche Ausnutzung dieser Sicherheitslücke muss ein Benutzer eine bestimmte Aktion durchführen, bevor die Sicherheitslücke ausgenutzt werden kann. Beispielsweise kann eine erfolgreiche Ausnutzung nur während der Installation einer Anwendung durch einen Systemadministrator möglich sein."
            }
        },

        S: {
            C: {
                l: 'Changed',
                d: "<b>Das Schlimmste:</b> Eine ausgenutzte Schwachstelle kann sich auf Ressourcen außerhalb des Sicherheitsbereichs auswirken, der von der Sicherheitsbehörde der anfälligen Komponente verwaltet wird. In diesem Fall sind die verwundbare Komponente und die betroffene Komponente unterschiedlich und werden von verschiedenen Sicherheitsbehörden verwaltet."
            },
            U: {
                l: 'Unchanged',
                d: "<b>Schlecht:</b> Eine ausgenutzte Schwachstelle kann nur Ressourcen betreffen, die von derselben Sicherheitsbehörde verwaltet werden. In diesem Fall sind die verwundbare Komponente und die betroffene Komponente entweder identisch oder beide werden von derselben Sicherheitsbehörde verwaltet."
            }
        },
        C: {
            H: {
                l: 'High',
                d: "<b>Das Schlimmste:</b> Es kommt zu einem totalen Verlust der Vertraulichkeit, was dazu führt, dass alle Ressourcen innerhalb der betroffenen Komponente für den Angreifer offengelegt werden. Oder es wird nur Zugang zu einigen eingeschränkten Informationen erlangt, aber die offengelegten Informationen haben direkte, schwerwiegende Auswirkungen. Ein Angreifer stiehlt beispielsweise das Kennwort des Administrators oder die privaten Verschlüsselungsschlüssel eines Webservers."
            },
            L: {
                l: 'Low',
                d: "<b>Schlecht:</b> Es gibt einen gewissen Verlust an Vertraulichkeit. Der Angreifer hat jedoch keine Kontrolle darüber, welche Informationen er erlangt, oder der Umfang oder die Art des Verlusts ist begrenzt. Die Offenlegung von Informationen führt nicht zu einem direkten, ernsthaften Schaden für die betroffene Komponente."
            },
            N: {
                l: 'None',
                d: "<b>Gut:</b> Es gibt keinen Verlust der Vertraulichkeit innerhalb der betroffenen Komponente."
            }
        },
        I: {
            H: {
                l: 'High',
                d: "<b>Das Schlimmste:</b> Es kommt zu einem totalen Verlust der Integrität oder zu einem vollständigen Verlust des Schutzes. Der Angreifer ist beispielsweise in der Lage, alle Dateien zu ändern, die von der betroffenen Komponente geschützt werden. Oder es können nur einige Dateien geändert werden, aber eine böswillige Änderung hätte unmittelbare, schwerwiegende Folgen für die betroffene Komponente."
            },
            L: {
                l: 'Low',
                d: "<b>Schlecht:</b> Die Änderung von Daten ist möglich, aber der Angreifer hat keine Kontrolle über die Folgen einer Änderung, oder der Umfang der Änderung ist begrenzt. Die Datenänderung hat keine direkten, schwerwiegenden Auswirkungen auf die betroffene Komponente."
            },
            N: {
                l: 'None',
                d: "<b>Gut:</b> Es gibt keinen Verlust der Integrität innerhalb der betroffenen Komponente."
            }
        },
        A: {
            H: {
                l: 'High',
                d: "<b>Das Schlimmste:</b> Der Angreifer ist in der Lage, den Zugang zu den Ressourcen der betroffenen Komponente vollständig zu verweigern <ul><li>dieser Verlust ist entweder anhaltend (solange der Angreifer den Angriff durchführt) oder dauerhaft (der Zustand bleibt auch nach Abschluss des Angriffs bestehen). Oder der Angreifer ist in der Lage, einen Teil der Verfügbarkeit zu verweigern, aber der Verlust der Verfügbarkeit stellt eine unmittelbare, schwerwiegende Konsequenz für die betroffene Komponente dar (z. B. kann der Angreifer bestehende Verbindungen nicht unterbrechen, aber neue Verbindungen verhindern; der Angreifer kann wiederholt eine Schwachstelle ausnutzen, die bei jedem erfolgreichen Angriff nur einen kleinen Teil des Speichers leckt, aber nach wiederholter Ausnutzung dazu führt, dass ein Dienst vollständig nicht mehr verfügbar ist).</li></ul>"
            },
            L: {
                l: 'Low',
                d: "<b>Schlecht:</b> Die Leistung ist vermindert oder es kommt zu Unterbrechungen bei der Verfügbarkeit von Ressourcen. Selbst wenn eine wiederholte Ausnutzung der Schwachstelle möglich ist, hat der Angreifer nicht die Möglichkeit, den Dienst für legitime Benutzer vollständig zu verweigern. Die Ressourcen in der betroffenen Komponente sind entweder die ganze Zeit über teilweise oder nur zeitweise vollständig verfügbar, aber insgesamt gibt es keine direkten, ernsthaften Auswirkungen auf die betroffene Komponente."
            },
            N: {
                l: 'None',
                d: "<b>Gut:</b> Es gibt keine Auswirkungen auf die Verfügbarkeit innerhalb der betroffenen Komponente."
            }
        }
    };

    this.bme = {};
    this.bmgReg = {
        AV: 'NALP',
        AC: 'LH',
        PR: 'NLH',
        UI: 'NR',
        S: 'CU',
        C: 'HLN',
        I: 'HLN',
        A: 'HLN'
    };
    this.bmoReg = {
        AV: 'NALP',
        AC: 'LH',
        C: 'C',
        I: 'C',
        A: 'C'
    };
    var s, f, dl, g, dd, l;
    this.el = document.getElementById(id);
    this.el.appendChild(s = e('style'));
    s.innerHTML = '';
    this.el.appendChild(f = e('form'));
    f.className = 'cvssjs';
    this.calc = f;
    for (g in this.bg) {
        f.appendChild(dl = e('dl'));
        dl.setAttribute('class', g);
        var dt = e('dt');
        dt.innerHTML = this.bg[g];
        dl.appendChild(dt);
        for (s in this.bm[g]) {
            dd = e('dd');
            dl.appendChild(dd);
            var inp = e('input');
            inp.setAttribute('name', g);
            inp.setAttribute('value', s);
            inp.setAttribute('id', id + g + s);
            inp.setAttribute('class', g + s);
            //inp.setAttribute('ontouchstart', '');
            inp.setAttribute('type', 'radio');
            this.bme[g + s] = inp;
            var me = this;
            inp.onchange = function () {
                me.setMetric(this);
            };
            dd.appendChild(inp);
            l = e('label');
            dd.appendChild(l);
            l.setAttribute('for', id + g + s);
            l.appendChild(e('i')).setAttribute('class', g + s);
            l.appendChild(document.createTextNode(this.bm[g][s].l + ' '));
            dd.appendChild(e('small')).innerHTML = this.bm[g][s].d;
        }
    }
    //f.appendChild(e('hr'));
    f.appendChild(dl = e('dl'));
    dl.innerHTML = '<dt>Severity&sdot;Score&sdot;Vector</dt>';
    dd = e('dd');
    dl.appendChild(dd);
    l = dd.appendChild(e('label'));
    l.className = 'results';
    l.appendChild(this.severity = e('span'));
    this.severity.className = 'severity';
    l.appendChild(this.score = e('span'));
    this.score.className = 'score';
    l.appendChild(document.createTextNode(' '));
    l.appendChild(this.vector = e('a'));
    this.vector.className = 'vector';
    this.vector.innerHTML = 'CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_';
    // setup the copy button/icon
    l.appendChild(document.createTextNode(' '));
    l.appendChild(this.copyButton = e('a'))
    this.copyButton.style.visibility = "hidden"
    this.copyButton.className = "copy-button"
    this.copyButton.title = "Copy Vector to Clipboard"
    this.copyButton.innerHTML = 'Copy'
    this.copyButton.onclick = function () {
        navigator.clipboard.writeText(document.querySelector(".vector").innerText)
    }

    if (options.onsubmit) {
        f.appendChild(e('hr'));
        this.submitButton = f.appendChild(e('input'));
        this.submitButton.setAttribute('type', 'submit');
        this.submitButton.onclick = options.onsubmit;
    }
};

CVSS.prototype.severityRatings = [{
    name: "None",
    bottom: 0.0,
    top: 0.0
}, {
    name: "Low",
    bottom: 0.1,
    top: 3.9
}, {
    name: "Medium",
    bottom: 4.0,
    top: 6.9
}, {
    name: "High",
    bottom: 7.0,
    top: 8.9
}, {
    name: "Critical",
    bottom: 9.0,
    top: 10.0
}];

CVSS.prototype.severityRating = function (score) {
    var i;
    var severityRatingLength = this.severityRatings.length;
    for (i = 0; i < severityRatingLength; i++) {
        if (score >= this.severityRatings[i].bottom && score <= this.severityRatings[i].top) {
            return this.severityRatings[i];
        }
    }
    return {
        name: "?",
        bottom: 'Not',
        top: 'defined'
    };
};

CVSS.prototype.valueofradio = function(e) {
    for(var i = 0; i < e.length; i++) {
        if (e[i].checked) {
            return e[i].value;
        }
    }
    return null;
};

CVSS.prototype.calculate = function () {
    var cvssVersion = "3.1";
    var exploitabilityCoefficient = 8.22;
    var scopeCoefficient = 1.08;

    // Define associative arrays mapping each metric value to the constant used in the CVSS scoring formula.
    var Weight = {
        AV: {
            N: 0.85,
            A: 0.62,
            L: 0.55,
            P: 0.2
        },
        AC: {
            H: 0.44,
            L: 0.77
        },
        PR: {
            U: {
                N: 0.85,
                L: 0.62,
                H: 0.27
            },
            // These values are used if Scope is Unchanged
            C: {
                N: 0.85,
                L: 0.68,
                H: 0.5
            }
        },
        // These values are used if Scope is Changed
        UI: {
            N: 0.85,
            R: 0.62
        },
        S: {
            U: 6.42,
            C: 7.52
        },
        C: {
            N: 0,
            L: 0.22,
            H: 0.56
        },
        I: {
            N: 0,
            L: 0.22,
            H: 0.56
        },
        A: {
            N: 0,
            L: 0.22,
            H: 0.56
        }
        // C, I and A have the same weights

    };

    var p;
    var val = {}, metricWeight = {};
    try {
        for (p in this.bg) {
            val[p] = this.valueofradio(this.calc.elements[p]);
            if (typeof val[p] === "undefined" || val[p] === null) {
                return "?";
            }
            metricWeight[p] = Weight[p][val[p]];
        }
    } catch (err) {
        return err; // TODO: need to catch and return sensible error value & do a better job of specifying *which* parm is at fault.
    }
    metricWeight.PR = Weight.PR[val.S][val.PR];
    //
    // CALCULATE THE CVSS BASE SCORE
    //
    var roundUp1 = function Roundup(input) {
        var int_input = Math.round(input * 100000);
        if (int_input % 10000 === 0) {
            return int_input / 100000
        } else {
            return (Math.floor(int_input / 10000) + 1) / 10
        }
    };
    try {
    var baseScore, impactSubScore, impact, exploitability;
    var impactSubScoreMultiplier = (1 - ((1 - metricWeight.C) * (1 - metricWeight.I) * (1 - metricWeight.A)));
    if (val.S === 'U') {
        impactSubScore = metricWeight.S * impactSubScoreMultiplier;
    } else {
        impactSubScore = metricWeight.S * (impactSubScoreMultiplier - 0.029) - 3.25 * Math.pow(impactSubScoreMultiplier - 0.02, 15);
    }
    var exploitabalitySubScore = exploitabilityCoefficient * metricWeight.AV * metricWeight.AC * metricWeight.PR * metricWeight.UI;
    if (impactSubScore <= 0) {
        baseScore = 0;
    } else {
        if (val.S === 'U') {
            baseScore = roundUp1(Math.min((exploitabalitySubScore + impactSubScore), 10));
        } else {
            baseScore = roundUp1(Math.min((exploitabalitySubScore + impactSubScore) * scopeCoefficient, 10));
        }
    }

    return baseScore.toFixed(1);
    } catch (err) {
        return err;
    }
};

CVSS.prototype.get = function() {
    return {
        score: this.score.innerHTML,
        vector: this.vector.innerHTML
    };
};

CVSS.prototype.setMetric = function(a) {
    var vectorString = this.vector.innerHTML;
    if (/AV:.\/AC:.\/PR:.\/UI:.\/S:.\/C:.\/I:.\/A:./.test(vectorString)) {} else {
        vectorString = 'AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_';
    }
    //e("E" + a.id).checked = true;
    var newVec = vectorString.replace(new RegExp('\\b' + a.name + ':.'), a.name + ':' + a.value);
    this.set(newVec);
};

CVSS.prototype.set = function(vec) {
    var newVec = 'CVSS:3.1/';
    var sep = '';
    for (var m in this.bm) {
        var match = (new RegExp('\\b(' + m + ':[' + this.bmgReg[m] + '])')).exec(vec);
        if (match !== null) {
            var check = match[0].replace(':', '');
            this.bme[check].checked = true;
            newVec = newVec + sep + match[0];
        } else if ((m in {C:'', I:'', A:''}) && (match = (new RegExp('\\b(' + m + ':C)')).exec(vec)) !== null) {
            // compatibility with v2 only for CIA:C
            this.bme[m + 'H'].checked = true;
            newVec = newVec + sep + m + ':H';
        } else {
            newVec = newVec + sep + m + ':_';
            for (var j in this.bm[m]) {
                this.bme[m + j].checked = false;
            }
        }
        sep = '/';
    }
    this.update(newVec);
};

CVSS.prototype.update = function(newVec) {
    this.vector.innerHTML = newVec;
    var s = this.calculate();
    this.score.innerHTML = s;
    var rating = this.severityRating(s);
    this.severity.className = rating.name + ' severity';
    this.severity.innerHTML = rating.name + '<sub>' + rating.bottom + ' - ' + rating.top + '</sub>';
    this.severity.title = rating.bottom + ' - ' + rating.top;
    if (rating['name'] != '?') {
        this.copyButton.style.visibility = "visible"
    }
    if (this.options !== undefined && this.options.onchange !== undefined) {
        this.options.onchange();
    }
};