/*
 * Get External IP address by STUN protocol
 *
 * Based on project Minimalistic STUN client "ministun"
 * https://code.google.com/p/ministun/
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 *
 * STUN is described in RFC3489 and it is based on the exchange
 * of UDP packets between a client and one or more servers to
 * determine the externally visible address (and port) of the client
 * once it has gone through the NAT boxes that connect it to the
 * outside.
 * The simplest request packet is just the header defined in
 * struct stun_header, and from the response we may just look at
 * one attribute, STUN_MAPPED_ADDRESS, that we find in the response.
 * By doing more transactions with different server addresses we
 * may determine more about the behaviour of the NAT boxes, of
 * course - the details are in the RFC.
 *
 * All STUN packets start with a simple header made of a type,
 * length (excluding the header) and a 16-byte random transaction id.
 * Following the header we may have zero or more attributes, each
 * structured as a type, length and a value (whose format depends
 * on the type, but often contains addresses).
 * Of course all fields are in network format.
 */

#include <inttypes.h>
#include <limits>
#include <string.h>
#include <sys/types.h>
#ifdef WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#endif
#include <time.h>

#include "ministun.h"
#include "netbase.h"

extern int GetRandInt(int nMax);
extern uint64_t GetRand(uint64_t nMax);

/*---------------------------------------------------------------------*/

struct StunSrv {
    char     name[46];
    uint16_t port;
};

/*---------------------------------------------------------------------*/
// STUN server list
static struct StunSrv StunSrvList[] = {
{"freestun.net",	3478},
{"relay.webwormhole.io",	3478},
{"stun-01.schulen-fulda.de",	3478},
{"stun-02.schulen-fulda.de",	3478},
{"stun-03.schulen-fulda.de",	3478},
{"stun-1.server.yesing.com",	3478},
{"stun-2nd.relaix.net",	3478},
{"stun-a01.isp.t-ipnet.de",	3478},
{"stun-americas-01.s73cloud.com",	3478},
{"stun-americas-02.s73cloud.com",	3478},
{"stun-azure.47billion.com",	3478},
{"stun-b1.qq.com",	3478},
{"stun-de.files.fm",	3478},
{"stun-dev.gozeppelin.com",	3478},
{"stun-neu.levigo.net",	3478},
{"stun-one.mabe.at",	3478},
{"stun-staging.videovisit.io",	3478},
{"stun-test.sip5060.net",	3478},
{"stun-turn.4realstudio.com",	3478},
{"stun-turn.alta.neopath.com.br",	3478},
{"stun-turn.demo.ikonixtechnology.com.au",	3478},
{"stun-turn.federowicz.de",	3478},
{"stun-v2.mdtalk.io",	3478},
{"stun.1-voip.com",	3478},
{"stun.12connect.com",	3478},
{"stun.12voip.com",	3478},
{"stun.1und1.de",	3478},
{"stun.3deluxe.de",	3478},
{"stun.3wayint.com",	3478},
{"stun.5222.de",	3478},
{"stun.5sn.com",	3478},
{"stun.6clones.net",	3478},
{"stun.aa.net.uk",	3478},
{"stun.aaisp.co.uk",	3478},
{"stun.abikus.pl",	3478},
{"stun.abracontrols.com",	3478},
{"stun.acquageraci.it",	3478},
{"stun.acrobits.cz",	3478},
{"stun.acronis.com",	3478},
{"stun.actionvoip.com",	3478},
{"stun.admira.com",	3478},
{"stun.adorsaz.ch",	3478},
{"stun.advantic.de",	3478},
{"stun.agya.info",	3478},
{"stun.alabasta.net",	3478},
{"stun.alberon.cz",	3478},
{"stun.allflac.com",	3478},
{"stun.alphacron.de",	3478},
{"stun.alpirsbacher.de",	3478},
{"stun.annatel.net",	3478},
{"stun.anonym.im",	3478},
{"stun.antisip.com",	3478},
{"stun.anura.io",	3478},
{"stun.ariso.ch",	3478},
{"stun.arkh-edu.ru",	3478},
{"stun.astimax.de",	3478},
{"stun.atagverwarming.nl",	3478},
{"stun.atlas-stiftung.ch",	3478},
{"stun.atnd.de",	3478},
{"stun.atomicparticles.eu",	3478},
{"stun.ausproof.com.au",	3478},
{"stun.autosystem.com",	3478},
{"stun.avigora.fr",	3478},
{"stun.avmeets.com",	3478},
{"stun.avoxi.com",	3478},
{"stun.awassif.eu",	3478},
{"stun.axeos.nl",	3478},
{"stun.axialys.net",	3478},
{"stun.b-tel.ir",	3478},
{"stun.babelforce.com",	3478},
{"stun.baltmannsweiler.de",	3478},
{"stun.bandmate.international",	3478},
{"stun.bandyer.com",	3478},
{"stun.bankai.de",	3478},
{"stun.bbb.vikosoz.de",	3478},
{"stun.bbb4all.de",	3478},
{"stun.bbnldevices.in",	3478},
{"stun.bbs1emden.org",	3478},
{"stun.bcs2005.net",	3478},
{"stun.beam.software",	3478},
{"stun.bearstech.com",	3478},
{"stun.bergophor.de",	3478},
{"stun.bernardoprovenzano.net",	3478},
{"stun.bestvoipreselling.com",	3478},
{"stun.bethesda.net",	3478},
{"stun.betta-security.de",	3478},
{"stun.bettfu.com",	3478},
{"stun.beuth-hochschule.de",	3478},
{"stun.bht-berlin.de",	3478},
{"stun.bisin.de",	3478},
{"stun.bitburger.de",	3478},
{"stun.bluesip.net",	3478},
{"stun.bmt.services",	3478},
{"stun.bnc.net",	3478},
{"stun.bnsth.com",	3478},
{"stun.bomgar.com",	3478},
{"stun.boulgour.com",	3478},
{"stun.bridesbay.com",	3478},
{"stun.broadtube.xyz",	3478},
{"stun.brodowski.org",	3478},
{"stun.bsrueti.ch",	3478},
{"stun.buechertraeume.de",	3478},
{"stun.c10r.facebook.com",	3478},
{"stun.cablenet-as.net",	3478},
{"stun.caderize.com",	3478},
{"stun.call.fr1.hotelservices.online",	3478},
{"stun.call.netplanet.at",	3478},
{"stun.callromania.ro",	3478},
{"stun.carlovizzini.it",	3478},
{"stun.ccc-ffm.de",	3478},
{"stun.cchgeu.ru",	3478},
{"stun.cdn-net.com",	3478},
{"stun.cdnbye.com",	3478},
{"stun.celering.io",	3478},
{"stun.cellmail.com",	3478},
{"stun.chaostreffbern.ch",	3478},
{"stun.chat.bilibili.com",	3478},
{"stun.chat.moh.gov.my",	3478},
{"stun.chatous.com",	3478},
{"stun.cheapvoip.com",	3478},
{"stun.cibercloud.com.br",	3478},
{"stun.circl.lu",	3478},
{"stun.clickphone.ro",	3478},
{"stun.cloud.trizwo.it",	3478},
{"stun.cnict.org",	3478},
{"stun.cnsconnect.nl",	3478},
{"stun.codepiraten.com",	3478},
{"stun.collabora-test.tim.it",	3478},
{"stun.commandnotfound.org",	3478},
{"stun.commpeak.com",	3478},
{"stun.comrex.com",	3478},
{"stun.conactive.de",	3478},
{"stun.coniservice.de",	3478},
{"stun.connectlife.it",	3478},
{"stun.consistec.de",	3478},
{"stun.coolmeet.co",	3478},
{"stun.cope.es",	3478},
{"stun.counterpath.com",	3478},
{"stun.counterpath.net",	3478},
{"stun.countryparksas.com",	3478},
{"stun.cozact.com",	3478},
{"stun.crazycall.com",	3478},
{"stun.crimeastar.net",	3478},
{"stun.csw2020.com.pl",	3478},
{"stun.ctafauni.it",	3478},
{"stun.d.lege.de",	3478},
{"stun.datajob.de",	3478},
{"stun.dataverse.de",	3478},
{"stun.datenschutz-experten.nrw",	3478},
{"stun.dcalling.de",	3478},
{"stun.dcentralisedmedia.com",	3478},
{"stun.deanone.nl",	3478},
{"stun.deepfinesse.com",	3478},
{"stun.defigohome.com",	3478},
{"stun.der-fetzer.de",	3478},
{"stun.deteque.com",	3478},
{"stun.dgt.lv",	3478},
{"stun.dice.tel",	3478},
{"stun.digitale-reparaturfabrik.com",	3478},
{"stun.dint.wroc.pl",	3478},
{"stun.dls.net",	3478},
{"stun.doctivi.com",	3478},
{"stun.doctoranywhere.mdit.gr",	3478},
{"stun.domostroitelnaya.com",	3478},
{"stun.drogoin.net",	3478},
{"stun.drvfst.de",	3478},
{"stun.dukun.de",	3478},
{"stun.dunyatelekom.com",	3478},
{"stun.dus.net",	3478},
{"stun.e-me.edu.gr",	3478},
{"stun.e.voiceinthecloud.io",	3478},
{"stun.easi.live",	3478},
{"stun.easter-eggs.com",	3478},
{"stun.easycallcloud.com",	3478},
{"stun.easytelecom.se",	3478},
{"stun.easyvoip.com",	3478},
{"stun.ecs-la.com",	3478},
{"stun.edvgarbe.de",	3478},
{"stun.edwin-wiegele.at",	3478},
{"stun.eeza.csic.es",	3478},
{"stun.einfachcallback.de",	3478},
{"stun.ekiga.net",	3478},
{"stun.eleusi.com",	3478},
{"stun.elevate.at",	3478},
{"stun.elitetele.com",	3478},
{"stun.engineeredarts.co.uk",	3478},
{"stun.enthalpy.mx",	3478},
{"stun.eol.co.nz",	3478},
{"stun.eoni.com",	3478},
{"stun.epic-bytes.net",	3478},
{"stun.epygi.com",	3478},
{"stun.erl.de",	3478},
{"stun.erre-elle.net",	3478},
{"stun.esprechstunde.net",	3478},
{"stun.eurosys.be",	3478},
{"stun.evgcdn.net",	3478},
{"stun.exirius.de",	3478},
{"stun.eyesoft.fr",	3478},
{"stun.f.haeder.net",	3478},
{"stun.factorify.cz",	3478},
{"stun.factoryaccess.cloud",	3478},
{"stun.fairytel.at",	3478},
{"stun.fakopats.de",	3478},
{"stun.fathomvoice.com",	3478},
{"stun.fba.accountants",	3478},
{"stun.fbsbx.com",	3478},
{"stun.fc-net.work",	3478},
{"stun.files.fm",	3478},
{"stun.filmplay.live",	3478},
{"stun.finanz-forum.biz",	3478},
{"stun.fitauto.ru",	3478},
{"stun.fixup.net",	3478},
{"stun.fk4.hs-bremen.de",	3478},
{"stun.fmo.de",	3478},
{"stun.foad.me.uk",	3478},
{"stun.folia.de",	3478},
{"stun.fon.is",	3478},
{"stun.foncloud.net",	3478},
{"stun.framasoft.org",	3478},
{"stun.freecall.com",	3478},
{"stun.freeswitch.org",	3478},
{"stun.freevoipdeal.com",	3478},
{"stun.frozenmountain.com",	3478},
{"stun.futurasp.es",	3478},
{"stun.gadgeteers.net",	3478},
{"stun.galeriemagnet.at",	3478},
{"stun.gazl.co",	3478},
{"stun.gbmtrade.it",	3478},
{"stun.gbtel.ca",	3478},
{"stun.gectsolutions.com",	3478},
{"stun.geesthacht.de",	3478},
{"stun.gehrmann.vip",	3478},
{"stun.genymotion.com",	3478},
{"stun.geonet.ro",	3478},
{"stun.gigaset.net",	3478},
{"stun.gimeco.it",	3478},
{"stun.globenet.org",	3478},
{"stun.gmx.de",	3478},
{"stun.gmx.net",	3478},
{"stun.gntel.nl",	3478},
{"stun.godatenow.com",	3478},
{"stun.goldfish.ie",	3478},
{"stun.gonicus.de",	3478},
{"stun.gooodcare.com",	3478},
{"stun.graftlab.com",	3478},
{"stun.grazertrinkwasseringefahr.at",	3478},
{"stun.greedy-it.de",	3478},
{"stun.grunet.de",	3478},
{"stun.gtov.net",	3478},
{"stun.gveh.de",	3478},
{"stun.hacklab.fi",	3478},
{"stun.halloapp.dev",	3478},
{"stun.halonet.pl",	3478},
{"stun.healthtap.com",	3478},
{"stun.heeds.eu",	3478},
{"stun.heldenvz.de",	3478},
{"stun.herweck.de",	3478},
{"stun.hfg-karlsruhe.de",	3478},
{"stun.hialabs.com",	3478},
{"stun.hicare.net",	3478},
{"stun.hide.me",	3478},
{"stun.hitv.com",	3478},
{"stun.hivestreaming.com",	3478},
{"stun.hivestreaming.trafficmanager.net",	3478},
{"stun.hoiio.com",	3478},
{"stun.holocom.cloud",	3478},
{"stun.honeycall.com",	3478},
{"stun.hoolva.com",	3478},
{"stun.hopsync.org",	3478},
{"stun.hot-chilli.net",	3478},
{"stun.hubnetweb.org",	3478},
{"stun.ibi.multiq.com",	3478},
{"stun.ictp.it",	3478},
{"stun.icuconnect.eu",	3478},
{"stun.ied.sma.de",	3478},
{"stun.ifon.pl",	3478},
{"stun.ignion.net",	3478},
{"stun.iiitkottayam.ac.in",	3478},
{"stun.ilam.ac.ir",	3478},
{"stun.ilya.ws",	3478},
{"stun.imafex.sk",	3478},
{"stun.imeeting.com.br",	3478},
{"stun.imp.ch",	3478},
{"stun.impactpbx.com",	3478},
{"stun.indisoft.de",	3478},
{"stun.indycall.com",	3478},
{"stun.infra.net",	3478},
{"stun.insemex.ro",	3478},
{"stun.insoftusa.com",	3478},
{"stun.internetcalls.com",	3478},
{"stun.intervoip.com",	3478},
{"stun.intwizja.pl",	3478},
{"stun.inubo.ch",	3478},
{"stun.inyar.ru",	3478},
{"stun.iointegrators.com",	3478},
{"stun.ionewu.com",	3478},
{"stun.iossol.de",	3478},
{"stun.iotalk.ir",	3478},
{"stun.ipeex.de",	3478},
{"stun.ipfsbit.com",	3478},
{"stun.ippi.com",	3478},
{"stun.ippi.fr",	3478},
{"stun.ipshka.com",	3478},
{"stun.ipv8.pl",	3478},
{"stun.iqvoice.com",	3478},
{"stun.irishvoip.com",	3478},
{"stun.iserv.eu",	3478},
{"stun.isp.net.au",	3478},
{"stun.istitutogramscisiciliano.it",	3478},
{"stun.it1.hr",	3478},
{"stun.iut.ac.ir",	3478},
{"stun.ixc.ua",	3478},
{"stun.jabber.dk",	3478},
{"stun.jabbim.cz",	3478},
{"stun.jay.net",	3478},
{"stun.jensbouma.com",	3478},
{"stun.jerichosystems.co.za",	3478},
{"stun.johanhelsing.studio",	3478},
{"stun.jowisoftware.de",	3478},
{"stun.jrnetservices.de",	3478},
{"stun.jukno.de",	3478},
{"stun.jumblo.com",	3478},
{"stun.jump-up.to",	3478},
{"stun.junet.se",	3478},
{"stun.justvoip.com",	3478},
{"stun.k8s.xpertyme.com",	3478},
{"stun.kalis.cc",	3478},
{"stun.kanne.ggeg.eu",	3478},
{"stun.kanojo.de",	3478},
{"stun.kaseya.com",	3478},
{"stun.kc.com.pl",	3478},
{"stun.kedr.io",	3478},
{"stun.kempen.xyz",	3478},
{"stun.kenkon.net",	3478},
{"stun.kleen.ch",	3478},
{"stun.kleusberg.de",	3478},
{"stun.kohrn-online.de",	3478},
{"stun.komsa.de",	3478},
{"stun.komunikas.net",	3478},
{"stun.kotter.net",	3478},
{"stun.kpi.ua",	3478},
{"stun.krypto.casa",	3478},
{"stun.kserver.org",	3478},
{"stun.kuva-dev.eticlab.xyz",	3478},
{"stun.l.google.com",	19302},
{"stun.l.google.com",	19305},
{"stun.l.google.com",	3478},
{"stun.labs.net",	3478},
{"stun.ladridiricette.it",	3478},
{"stun.landvast.nl",	3478},
{"stun.lebendigefluesse.at",	3478},
{"stun.lege.de",	3478},
{"stun.lender.schule",	3478},
{"stun.leonde.org",	3478},
{"stun.leucotron.com.br",	3478},
{"stun.levigo.de",	3478},
{"stun.levigo.net",	3478},
{"stun.likenuuk.com",	3478},
{"stun.lineaencasa.com",	3478},
{"stun.linphone.org",	3478},
{"stun.linss.com",	3478},
{"stun.linuxtrent.it",	3478},
{"stun.lirmm.fr",	3478},
{"stun.live2u.com.br",	3478},
{"stun.liveo.fr",	3478},
{"stun.lleida.net",	3478},
{"stun.localphone.com",	3478},
{"stun.logic.ky",	3478},
{"stun.lovense.com",	3478},
{"stun.lowratevoip.com",	3478},
{"stun.lrhmv.de",	3478},
{"stun.lu-cix.lu",	3478},
{"stun.luger.de",	3478},
{"stun.luhr.net",	3478},
{"stun.luzzato.com",	3478},
{"stun.lysergic.dev",	3478},
{"stun.m-online.net",	3478},
{"stun.madavi.de",	3478},
{"stun.magicum.net",	3478},
{"stun.maitri.club",	3478},
{"stun.marcelproust.it",	3478},
{"stun.marko-jovanovic.de",	3478},
{"stun.mazewebsolutions.ch",	3478},
{"stun.mconf.rnp.br",	3478},
{"stun.mcra.fr",	3478},
{"stun.mdcc.de",	3478},
{"stun.med.uni-greifswald.de",	3478},
{"stun.mediani.de",	3478},
{"stun.medvc.eu",	3478},
{"stun.meetwife.com",	3478},
{"stun.megatel.si",	3478},
{"stun.meowsbox.com",	3478},
{"stun.metra-services.de",	3478},
{"stun.microdata.co.uk",	3478},
{"stun.microdata.systems",	3478},
{"stun.mikuru.de",	3478},
{"stun.miwifi.com",	3478},
{"stun.mixvoip.com",	3478},
{"stun.mobile-italia.com",	3478},
{"stun.moonlight-stream.org",	3478},
{"stun.morgan-systems.com",	3478},
{"stun.mtx.prudent.io",	3478},
{"stun.muoversi.net",	3478},
{"stun.myhowto.org",	3478},
{"stun.myspeciality.com",	3478},
{"stun.myvoipapp.com",	3478},
{"stun.myvoiptraffic.com",	3478},
{"stun.mywatson.it",	3478},
{"stun.nagoonline.com",	3478},
{"stun.nanocosmos.de",	3478},
{"stun.ncic.com",	3478},
{"stun.nekkimobile.ru",	3478},
{"stun.neobridge.fr",	3478},
{"stun.neomedia.it",	3478},
{"stun.neowise.fr",	3478},
{"stun.netappel.com",	3478},
{"stun.netensia.net",	3478},
{"stun.netgsm.com.tr",	3478},
{"stun.netmaster.ro",	3478},
{"stun.netzbegruenung.de",	3478},
{"stun.neura.datamicron.com",	3478},
{"stun.nexphone.ch",	3478},
{"stun.next-gen.ro",	3478},
{"stun.next.nortelmed.com",	3478},
{"stun.nextcloud.com",	3478},
{"stun.nextcloud.com",	443},
{"stun.nexttell.ru",	3478},
{"stun.nexxtmobile.de",	3478},
{"stun.nfon.net",	3478},
{"stun.nicolai-wolff.de",	3478},
{"stun.nicoll.xyz",	3478},
{"stun.ninda.net",	3478},
{"stun.nonoh.net",	3478},
{"stun.noonan.family",	3478},
{"stun.nortelmed.com",	3478},
{"stun.nowe-tmg.de",	3478},
{"stun.odsh.de",	3478},
{"stun.officinabit.com",	3478},
{"stun.oldhamtechnology.com",	3478},
{"stun.olimontel.it",	3478},
{"stun.oncloud7.ch",	3478},
{"stun.openjobs.hu",	3478},
{"stun.openmedia.gallery",	3478},
{"stun.openmusic.gallery",	3478},
{"stun.openvoip.it",	3478},
{"stun.optdyn.com",	3478},
{"stun.ora.pm",	3478},
{"stun.ortopediacoam.it",	3478},
{"stun.p2p.blackberry.com",	3478},
{"stun.palava.tv",	3478},
{"stun.partell.nl",	3478},
{"stun.patentanimal.com",	3478},
{"stun.pbx.netcomnetz.de",	3478},
{"stun.pbx.scsynergy.net",	3478},
{"stun.peekvideochat.com",	3478},
{"stun.peeters.com",	3478},
{"stun.peethultra.be",	3478},
{"stun.petiak.ir",	3478},
{"stun.petzi-net.de",	3478},
{"stun.phoenixbell.online",	3478},
{"stun.phone.com",	3478},
{"stun.phx.freevoicepbx.com",	3478},
{"stun.physics.uoc.gr",	3478},
{"stun.piratenbrandenburg.de",	3478},
{"stun.pjsip.org",	3478},
{"stun.planetarium.com.br",	3478},
{"stun.plexicomm.net",	3478},
{"stun.pocos.nl",	3478},
{"stun.poetamatusel.org",	3478},
{"stun.poivy.com",	3478},
{"stun.portal.hivetechnology.net",	3478},
{"stun.portalnetworks.ca",	3478},
{"stun.portfiftysixty.net",	3478},
{"stun.postblue.info",	3478},
{"stun.poul.org",	3478},
{"stun.powervoip.com",	3478},
{"stun.ppcsystem.online",	3478},
{"stun.ppdi.com",	3478},
{"stun.prestatel.fr",	3478},
{"stun.pricall.eu",	3478},
{"stun.prism.it",	3478},
{"stun.prometheanproduct.com",	3478},
{"stun.prov-2115.ovh",	3478},
{"stun.provelo.org",	3478},
{"stun.provtel.com",	3478},
{"stun.prozserin.org",	3478},
{"stun.psych.help",	3478},
{"stun.pure-ip.com",	3478},
{"stun.purtel.com",	3478},
{"stun.q-mex.net",	3478},
{"stun.qcol.net",	3478},
{"stun.quirum.com",	3478},
{"stun.radiojar.com",	3478},
{"stun.rcsxzx.com",	3478},
{"stun.redbini.com",	3478},
{"stun.redmedical.de",	3478},
{"stun.redsquared.com",	3478},
{"stun.relaix.net",	3478},
{"stun.remotepc.com",	3478},
{"stun.remotetopc.com",	3478},
{"stun.rescuetrack.com",	3478},
{"stun.ringostat.com",	3478},
{"stun.robbuvoice.com",	3478},
{"stun.rockenstein.de",	3478},
{"stun.roct.de",	3478},
{"stun.rolmail.net",	3478},
{"stun.rolvoice.it",	3478},
{"stun.romaaeterna.nl",	3478},
{"stun.romancecompass.com",	3478},
{"stun.root-1.de",	3478},
{"stun.rtc.praxxys.ph",	3478},
{"stun.rtc.yandex.net",	3478},
{"stun.ru-brides.com",	3478},
{"stun.rxdbit.com",	3478},
{"stun.rynga.com",	3478},
{"stun.rz.htw-berlin.de",	3478},
{"stun.sacko.com.au",	3478},
{"stun.saman360.com",	3478},
{"stun.schlund.de",	3478},
{"stun.schmid-federn.ch",	3478},
{"stun.schoeffel.de",	3478},
{"stun.schulinformatik.at",	3478},
{"stun.scorecrm.pe",	3478},
{"stun.scriptonary.com",	3478},
{"stun.scudcrm.com",	3478},
{"stun.seemoo.tu-darmstadt.de",	3478},
{"stun.selasky.org",	3478},
{"stun.sensor.community",	3478},
{"stun.serveil.com",	3478},
{"stun.server.uni-frankfurt.de",	3478},
{"stun.serverplantage.de",	3478},
{"stun.servileto.net",	3478},
{"stun.sewan.fr",	3478},
{"stun.shadrinsk.net",	3478},
{"stun.shared.bbmenterprise.com",	3478},
{"stun.shared.bbmenterprise.dyn.blackberry.net",	3478},
{"stun.shwechat.com",	3478},
{"stun.sice.com",	3478},
{"stun.sid.galaxie.family",	3478},
{"stun.siedle.com",	3478},
{"stun.sightline.se",	3478},
{"stun.sigmavoip.com",	3478},
{"stun.signalwire.com",	3478},
{"stun.signet.nl",	3478},
{"stun.simlar.org",	3478},
{"stun.simonbalzer.de",	3478},
{"stun.simulcast.eu",	3478},
{"stun.sip.us",	3478},
{"stun.sipdiscount.com",	3478},
{"stun.sipgate.net",	10000},
{"stun.sipgate.net",	3478},
{"stun.sipglobalphone.com",	3478},
{"stun.siplogin.de",	3478},
{"stun.sippeer.dk",	3478},
{"stun.sipthor.net",	3478},
{"stun.siptraffic.com",	3478},
{"stun.siptrunk.com",	3478},
{"stun.sipy.cz",	3478},
{"stun.skerric.com",	3478},
{"stun.sky.od.ua",	3478},
{"stun.skydrone.aero",	3478},
{"stun.sma.de",	3478},
{"stun.smartvoip.com",	3478},
{"stun.smsdiscount.com",	3478},
{"stun.smslisto.com",	3478},
{"stun.smvhost.in",	3478},
{"stun.soho66.co.uk",	3478},
{"stun.solcon.nl",	3478},
{"stun.solnet.ch",	3478},
{"stun.solomo.de",	3478},
{"stun.sonderformat.cloud",	3478},
{"stun.sonetel.com",	3478},
{"stun.sonetel.net",	3478},
{"stun.sparvoip.de",	3478},
{"stun.speakswitch.com",	3478},
{"stun.splicecom.com",	3478},
{"stun.sproesser.net",	3478},
{"stun.srca.org.sa",	3478},
{"stun.srce.hr",	3478},
{"stun.ssh.thinkrosystem.com",	3478},
{"stun.stadtwerke-eutin.de",	3478},
{"stun.steambot.ch",	3478},
{"stun.steuerkanzlei-banse.de",	3478},
{"stun.stochastix.de",	3478},
{"stun.stomp.dynv6.net",	3478},
{"stun.stratusvideo.com",	3478},
{"stun.streamnow.ch",	3478},
{"stun.streamspace.ai",	3478},
{"stun.studio-link.de",	3478},
{"stun.studio71.it",	3478},
{"stun.stuffnet.sk",	3478},
{"stun.stura.uni-heidelberg.de",	3478},
{"stun.superiordigital7.com",	3478},
{"stun.swrag.de",	3478},
{"stun.sylaps.com",	3478},
{"stun.syncthing.net",	3478},
{"stun.synergiejobs.be",	3478},
{"stun.syrex.co.za",	3478},
{"stun.syscon.cloud",	3478},
{"stun.szbboys.com",	3478},
{"stun.szlovak.sk",	3478},
{"stun.t-online.de",	3478},
{"stun.talkho.com",	3478},
{"stun.taxsee.com",	3478},
{"stun.teambox.fr",	3478},
{"stun.teamfon.com",	3478},
{"stun.teamfon.de",	3478},
{"stun.techlevel.org",	3478},
{"stun.technologpark.net",	3478},
{"stun.technosens.fr",	3478},
{"stun.tee.gr",	3478},
{"stun.tel.lu",	3478},
{"stun.tel.yandex.net",	3478},
{"stun.tel2.co.uk",	3478},
{"stun.telbo.com",	3478},
{"stun.teliax.com",	3478},
{"stun.telnyx.com",	3478},
{"stun.telviva.com",	3478},
{"stun.telxl.org",	3478},
{"stun.thebrassgroup.it",	3478},
{"stun.thegroovesurfers.live",	3478},
{"stun.thinkrosystem.com",	3478},
{"stun.threema.ch",	3478},
{"stun.thw-pbx.de",	3478},
{"stun.tichiamo.it",	3478},
{"stun.tixeo.com",	3478},
{"stun.tng.de",	3478},
{"stun.tor.yakdigitalphone.ca",	3478},
{"stun.totalcom.info",	3478},
{"stun.touchapp.cl",	3478},
{"stun.tretas.org",	3478},
{"stun.tricasting.com",	3478},
{"stun.ttmath.org",	3478},
{"stun.tula.nu",	3478},
{"stun.twt.it",	3478},
{"stun.u5fgb.com",	3478},
{"stun.uabrides.com",	3478},
{"stun.ucanet.ru",	3478},
{"stun.ukh.de",	3478},
{"stun.uls.co.za",	3478},
{"stun.ultrino.net",	3478},
{"stun.unearth.de",	3478},
{"stun.unimatrix.link",	3478},
{"stun.unimewo.com",	3478},
{"stun.univ-grenoble-alpes.fr",	3478},
{"stun.unotel.dk",	3478},
{"stun.uplinklabs.net",	3478},
{"stun.url.net.au",	3478},
{"stun.vadacom.co.nz",	3478},
{"stun.vallcom.it",	3478},
{"stun.var6.cn",	3478},
{"stun.vavadating.com",	3478},
{"stun.vc.itgen.io",	3478},
{"stun.vcomm.ca",	3478},
{"stun.verbo.be",	3478},
{"stun.vesrv.eu",	3478},
{"stun.vetlab.pl",	3478},
{"stun.video.taxi",	3478},
{"stun.videovisit.io",	3478},
{"stun.virtual-aula.com",	3478},
{"stun.visselhoevede.de",	3478},
{"stun.vivell.de",	3478},
{"stun.vivox.com",	3478},
{"stun.vjoon.com",	3478},
{"stun.vo.lu",	3478},
{"stun.voiceflex.com",	3478},
{"stun.voicehost.co.uk",	3478},
{"stun.voicetech.se",	3478},
{"stun.voicetrading.com",	3478},
{"stun.voip.aebc.com",	3478},
{"stun.voip.blackberry.com",	3478},
{"stun.voip.ciphertv.com",	3478},
{"stun.voip.dyn.blackberry.net",	3478},
{"stun.voip.eutelia.it",	3478},
{"stun.voip.ovh.net",	3478},
{"stun.voipawesome.com",	3478},
{"stun.voipblast.com",	3478},
{"stun.voipbuster.com",	3478},
{"stun.voipbusterpro.com",	3478},
{"stun.voipcheap.co.uk",	3478},
{"stun.voipcheap.com",	3478},
{"stun.voipconnect.com",	3478},
{"stun.voipdiscount.com",	3478},
{"stun.voipeasy.it",	3478},
{"stun.voipfibre.com",	3478},
{"stun.voipgain.com",	3478},
{"stun.voipgate.com",	3478},
{"stun.voipgateway.cloud",	3478},
{"stun.voipgrid.nl",	3478},
{"stun.voipia.net",	3478},
{"stun.voipinfocenter.com",	3478},
{"stun.voipoperator.tel",	3478},
{"stun.voippro.com",	3478},
{"stun.voipraider.com",	3478},
{"stun.voipstreet.com",	3478},
{"stun.voipstunt.com",	3478},
{"stun.voipsvr.net",	3478},
{"stun.voipvoice.it",	3478},
{"stun.voipvox.it",	3478},
{"stun.voipwise.com",	3478},
{"stun.voipxs.nl",	3478},
{"stun.voipzoom.com",	3478},
{"stun.voismart.com",	3478},
{"stun.vomessen.de",	3478},
{"stun.voys.nl",	3478},
{"stun.vozelia.com",	3478},
{"stun.voztele.com",	3478},
{"stun.voztovoice.org",	3478},
{"stun.vsrv1.shcwagenfeld.de",	3478},
{"stun.waterpolopalermo.it",	3478},
{"stun.wazo.io",	3478},
{"stun.wcoil.com",	3478},
{"stun.webcalldirect.com",	3478},
{"stun.webmatrix.com.br",	3478},
{"stun.webrtc.docety.com",	3478},
{"stun.webrtc.ecl.ntt.com",	3478},
{"stun.webtools.co.cr",	3478},
{"stun.weeb.fi",	3478},
{"stun.wemag.com",	3478},
{"stun.westtel.ky",	3478},
{"stun.wia.cz",	3478},
{"stun.wlvoip.net",	3478},
{"stun.wollgast-it.de",	3478},
{"stun.worship.com.ng",	3478},
{"stun.wowitel.net",	3478},
{"stun.wtfismyip.com",	3478},
{"stun.wuliangroup.cn",	3478},
{"stun.wws.link",	3478},
{"stun.wxnz.net",	3478},
{"stun.xmpp.masgalor.de",	3478},
{"stun.xooloo-messenger.com",	3478},
{"stun.xtekserver.com",	3478},
{"stun.xten.com",	3478},
{"stun.xx-on.de",	3478},
{"stun.yesdates.com",	3478},
{"stun.yesdok.com",	3478},
{"stun.yollacalls.com",	3478},
{"stun.zadarma.com",	3478},
{"stun.zebraduck.com",	3478},
{"stun.zenbakaitz.com",	3478},
{"stun.zentauron.de",	3478},
{"stun.zepf.uni-landau.de",	3478},
{"stun.zerobudget.design",	3478},
{"stun.zoomitel.net",	3478},
{"stun.zorra.com",	3478},
{"stun.zt.gets-it.net",	3478},
{"stun.ztrig.com",	3478},
{"stun.zugschlus.de",	3478},
{"stun0-ams.voipgrid.nl",	3478},
{"stun0-grq.voipgrid.nl",	3478},
{"stun0.appello.care",	3478},
{"stun0.eigenlinks.com",	3478},
{"stun0.yoyogi.de",	3478},
{"stun00.mirz.uni-jena.de",	3478},
{"stun00.webkonferenz.net",	3478},
{"stun001.yesdok.com",	3478},
{"stun01.ash-netconsult.de",	3478},
{"stun01.lith.dls.net",	3478},
{"stun01.livesale.cz",	3478},
{"stun01.mconf.rnp.br",	3478},
{"stun01.nfon.net",	3478},
{"stun01.pegasusserver.de",	3478},
{"stun01.silentcircle.net",	3478},
{"stun01.umy.ac.id",	3478},
{"stun02.counsol.net",	3478},
{"stun02.mconf.rnp.br",	3478},
{"stun02.nfon.net",	3478},
{"stun02.senfcall.de",	3478},
{"stun02.silentcircle.net",	3478},
{"stun02.umy.ac.id",	3478},
{"stun02.unifiedring.co.uk",	3478},
{"stun1.1telecom.ru",	3478},
{"stun1.a3bcproxy.nl",	3478},
{"stun1.alphacron.de",	3478},
{"stun1.anc.ffm.hfosip.de",	3478},
{"stun1.appello.care",	3478},
{"stun1.apse1.qa3.xhoot.com",	3478},
{"stun1.backend.doc-cirrus.com",	3478},
{"stun1.bancaditalia.it",	3478},
{"stun1.celya.fr",	3478},
{"stun1.crossmarx.nl",	3478},
{"stun1.dimorf.com",	3478},
{"stun1.doc-cirrus.com",	3478},
{"stun1.edagram.com",	3478},
{"stun1.egap.xunta.gal",	3478},
{"stun1.estpak.ee",	3478},
{"stun1.euc1.dev1.xhoot.com",	3478},
{"stun1.euc1.qa3.xhoot.com",	3478},
{"stun1.fra3.ffm.hfosip.de",	3478},
{"stun1.haluska.dev",	3478},
{"stun1.hfosip.de",	3478},
{"stun1.hoolva.com",	3478},
{"stun1.l.google.com",	19302},
{"stun1.l.google.com",	19305},
{"stun1.l.google.com",	3478},
{"stun1.mcra.fr",	3478},
{"stun1.meetby.io",	3478},
{"stun1.megatel.si",	3478},
{"stun1.mk.de",	3478},
{"stun1.mydisk.nsc.ru",	3478},
{"stun1.net.ipl.pt",	3478},
{"stun1.oren.cloud",	3478},
{"stun1.pocos.nl",	3478},
{"stun1.sipport.de",	3478},
{"stun1.starman.ee",	3478},
{"stun1.use1.dev1.xhoot.com",	3478},
{"stun1.use1.dev2.xhoot.com",	3478},
{"stun1.use1.dev3.xhoot.com",	3478},
{"stun1.use1.qa2.xhoot.com",	3478},
{"stun1.use1.qa3.xhoot.com",	3478},
{"stun1.vodaway.ru",	3478},
{"stun1.webweaver.de",	3478},
{"stun10.onewebtalk.de",	3478},
{"stun1a.anc.ffm.hfosip.de",	3478},
{"stun1a.fra3.ffm.hfosip.de",	3478},
{"stun1a.frontlinebackoffice.ca",	3478},
{"stun1a.novuscom.net",	3478},
{"stun1b.frontlinebackoffice.ca",	3478},
{"stun1b.novuscom.net",	3478},
{"stun2.1-voip.com",	3478},
{"stun2.1ats.ru",	3478},
{"stun2.a3bcproxy.nl",	3478},
{"stun2.appello.care",	3478},
{"stun2.backend.doc-cirrus.com",	3478},
{"stun2.bancaditalia.it",	3478},
{"stun2.belowtoxic.cloud",	3478},
{"stun2.call.netplanet.at",	3478},
{"stun2.doc-cirrus.com",	3478},
{"stun2.egap.xunta.gal",	3478},
{"stun2.fon.is",	3478},
{"stun2.free-solutions.org",	3478},
{"stun2.hoolva.com",	3478},
{"stun2.informatica95.net",	3478},
{"stun2.kynaforkids.vn",	3478},
{"stun2.l.google.com",	19302},
{"stun2.l.google.com",	19305},
{"stun2.meowsbox.com",	3478},
{"stun2.mik.ua",	3478},
{"stun2.mk.de",	3478},
{"stun2.net.ipl.pt",	3478},
{"stun2.pylo.net",	3478},
{"stun2.rz.htw-berlin.de",	3478},
{"stun2.server.uni-frankfurt.de",	3478},
{"stun2.sipport.de",	3478},
{"stun2.squaretalk.com",	3478},
{"stun2.ssystems.de",	3478},
{"stun2.starman.ee",	3478},
{"stun2.teletek.se",	3478},
{"stun2.videovisit.io",	3478},
{"stun2.wollgast-it.de",	3478},
{"stun2.zoomitel.net",	3478},
{"stun2a.frontlinebackoffice.ca",	3478},
{"stun2a.novuscom.net",	3478},
{"stun2a.southislandcable.com",	3478},
{"stun2b.frontlinebackoffice.ca",	3478},
{"stun2b.novuscom.net",	3478},
{"stun2b.southislandcable.com",	3478},
{"stun3.hoolva.com",	3478},
{"stun3.l.google.com",	19302},
{"stun3.l.google.com",	19305},
{"stun4.beeznest.com",	3478},
{"stun4.hoolva.com",	3478},
{"stun4.l.google.com",	19302},
{"stun4.l.google.com",	19305},
{"stun4.l.google.com",	3478},
{"stuna.wxnz.net",	3478},
{"stunb.wxnz.net",	3478},
{"stunbb.mirhosting.com",	3478},
{"stunc.cloud.trizwo.it",	3478},
{"stund.yeastar.com",	3478},
{"stundev-aws-secondary.rd01.konami.net",	3478},
{"stundev-aws-tertiary.rd01.konami.net",	3478},
{"stundev.livextend.cloud",	3478},
{"stunrc.ruijienetworks.com",	3478},
{"stuns.ipv8.pl",	3478},
{"stuns.nowe-tmg.de",	3478},
{"stuns.ztrig.com",	3478},
{"stunsec.provtel.com",	3478},
{"stunserver-if2.wx3.se",	3478},
{"stunserver.wx3.se",	3478},
{"stunsvr-as.ruijienetworks.com",	3478},
{"stunturn-se.easymeeting.net",	3478},
{"stunturn.sibtel.gv.at",	3478},
{"stunturn.yellka.com",	3478},
{"stunturn4.triart.jp",	3478},
{"stunv4.labs.lacnic.net",	3478},
{"stunvid.likenuuk.com",	3478},
{"stunx.externet.hu",	3478},
{"stunx.novuscom.net",	3478},
{"stuny.externet.hu",	3478},
{"stuny.megafone.hu",	3478},
{"stun.cloudflare.com",	3478},
{"stun.flashdance.cx",	3478}
};

static const int StunSrvListQty = sizeof(StunSrvList) / sizeof(StunSrv);

/* wrapper to send an STUN message */
static int stun_send(int s, struct sockaddr_in *dst, struct stun_header *resp)
{
    return sendto(s, (const char *)resp, ntohs(resp->msglen) + sizeof(*resp), 0,
                  (struct sockaddr *)dst, sizeof(*dst));
}

/* helper function to generate a random request id */
static uint64_t randfiller = GetRand(std::numeric_limits<uint64_t>::max());
static void stun_req_id(struct stun_header *req)
{
    const uint64_t *S_block = (const uint64_t *)StunSrvList;
    req->id.id[0] = GetRandInt(std::numeric_limits<int32_t>::max());
    req->id.id[1] = GetRandInt(std::numeric_limits<int32_t>::max());
    req->id.id[2] = GetRandInt(std::numeric_limits<int32_t>::max());
    req->id.id[3] = GetRandInt(std::numeric_limits<int32_t>::max());

    req->id.id[0] |= 0x55555555;
    req->id.id[1] &= 0x55555555;
    req->id.id[2] |= 0x55555555;
    req->id.id[3] &= 0x55555555;
    char x = 20;
    do {
        uint32_t s_elm = S_block[(uint8_t)randfiller];
        randfiller ^= (randfiller << 5) | (randfiller >> (64 - 5));
        randfiller += s_elm ^ x;
        req->id.id[x & 3] ^= randfiller + (randfiller >> 13);
    } while(--x);
}

/* callback type to be invoked on stun responses. */
typedef int (stun_cb_f)(struct stun_attr *attr, void *arg);

/* handle an incoming STUN message.
 *
 * Do some basic sanity checks on packet size and content,
 * try to extract a bit of information, and possibly reply.
 * At the moment this only processes BIND requests, and returns
 * the externally visible address of the request.
 * If a callback is specified, invoke it with the attribute.
 */
static int stun_handle_packet(int s, struct sockaddr_in *src,
                              unsigned char *data, size_t len, stun_cb_f *stun_cb, void *arg)
{
    struct stun_header *hdr = (struct stun_header *)data;
    struct stun_attr *attr;
    int ret = len;
    unsigned int x;

    /* On entry, 'len' is the length of the udp payload. After the
   * initial checks it becomes the size of unprocessed options,
   * while 'data' is advanced accordingly.
   */
    if (len < sizeof(struct stun_header))
        return -20;

    len -= sizeof(struct stun_header);
    data += sizeof(struct stun_header);
    x = ntohs(hdr->msglen); /* len as advertised in the message */
    if(x < len)
        len = x;

    while (len) {
        if (len < sizeof(struct stun_attr)) {
            ret = -21;
            break;
        }
        attr = (struct stun_attr *)data;
        /* compute total attribute length */
        x = ntohs(attr->len) + sizeof(struct stun_attr);
        if (x > len) {
            ret = -22;
            break;
        }
        stun_cb(attr, arg);
        //if (stun_process_attr(&st, attr)) {
        //  ret = -23;
        //  break;
        // }
        /* Clear attribute id: in case previous entry was a string,
     * this will act as the terminator for the string.
     */
        attr->attr = 0;
        data += x;
        len -= x;
    } // while
    /* Null terminate any string.
   * XXX NOTE, we write past the size of the buffer passed by the
   * caller, so this is potentially dangerous. The only thing that
   * saves us is that usually we read the incoming message in a
   * much larger buffer
   */
    *data = '\0';

    /* Now prepare to generate a reply, which at the moment is done
   * only for properly formed (len == 0) STUN_BINDREQ messages.
   */

    return ret;
}

/* Extract the STUN_MAPPED_ADDRESS from the stun response.
 * This is used as a callback for stun_handle_response
 * when called from stun_request.
 */
static int stun_get_mapped(struct stun_attr *attr, void *arg)
{
    struct stun_addr *addr = (struct stun_addr *)(attr + 1);
    struct sockaddr_in *sa = (struct sockaddr_in *)arg;

    if (ntohs(attr->attr) != STUN_MAPPED_ADDRESS || ntohs(attr->len) != 8)
        return 1; /* not us. */
    sa->sin_port = addr->port;
    sa->sin_addr.s_addr = addr->addr;
    return 0;
}

/*---------------------------------------------------------------------*/

static int StunRequest2(int sock, struct sockaddr_in *server, struct sockaddr_in *mapped) {

    struct stun_header *req;
    unsigned char reqdata[1024];

    req = (struct stun_header *)reqdata;
    stun_req_id(req);
    unsigned short reqlen = 0;
    req->msgtype = 0;
    req->msglen = 0;
    req->msglen = htons(reqlen);
    req->msgtype = htons(STUN_BINDREQ);

    unsigned char reply_buf[1024];
    fd_set rfds;
    struct timeval to = { STUN_TIMEOUT, 0 };
    struct sockaddr_in src;
#ifdef WIN32
    int srclen;
#else
    socklen_t srclen;
#endif

    int res = stun_send(sock, server, req);
    if(res < 0)
        return -10;
    FD_ZERO(&rfds);
    FD_SET(sock, &rfds);
    res = select(sock + 1, &rfds, NULL, NULL, &to);
    if (res <= 0)  /* timeout or error */
        return -11;
    memset(&src, 0, sizeof(src));
    srclen = sizeof(src);
    /* XXX pass -1 in the size, because stun_handle_packet might
   * write past the end of the buffer.
   */
    res = recvfrom(sock, (char *)reply_buf, sizeof(reply_buf) - 1,
                   0, (struct sockaddr *)&src, &srclen);
    if (res <= 0)
        return -12;
    memset(mapped, 0, sizeof(struct sockaddr_in));
    return stun_handle_packet(sock, &src, reply_buf, res, stun_get_mapped, mapped);
} // StunRequest2

/*---------------------------------------------------------------------*/
static int StunRequest(const char *host, uint16_t port, struct sockaddr_in *mapped) {
    struct hostent *hostinfo = gethostbyname(host);
    if(hostinfo == NULL)
        return -1;

    SOCKET sock = INVALID_SOCKET;
    struct sockaddr_in server, client;
    memset(&server, 0, sizeof(server));
    memset(&client, 0, sizeof(client));
    server.sin_family = client.sin_family = AF_INET;

    server.sin_addr = *(struct in_addr*) hostinfo->h_addr;
    server.sin_port = htons(port);

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock == INVALID_SOCKET)
        return -2;

    client.sin_addr.s_addr = htonl(INADDR_ANY);

    int rc = -3;
    if(bind(sock, (struct sockaddr*)&client, sizeof(client)) >= 0)
        rc = StunRequest2(sock, &server, mapped);
    CloseSocket(sock);
    return rc;
} // StunRequest

/*---------------------------------------------------------------------*/
// Input: two random values (pos, step) for generate uniuqe way over server
// list
// Output: populate struct struct mapped
// Retval:

int GetExternalIPbySTUN(uint64_t rnd, struct sockaddr_in *mapped, const char **srv) {
    randfiller    = rnd;
    uint16_t pos  = rnd;
    uint16_t step;
    do {
        rnd = (rnd >> 8) | 0xff00000000000000LL;
        step = rnd % StunSrvListQty;
    } while(step == 0);

    uint16_t attempt;
    for(attempt = 1; attempt < StunSrvListQty * 2; attempt++) {
        pos = (pos + step) % StunSrvListQty;
        int rc = StunRequest(*srv = StunSrvList[pos].name, StunSrvList[pos].port, mapped);
        if(rc >= 0)
            return attempt;
        // fprintf(stderr, "Lookup: %s:%u\t%s\t%d\n", StunSrvList[pos].name,
        // StunSrvList[pos].port, inet_ntoa(mapped->sin_addr), rc);
    }
    return -1;
}
