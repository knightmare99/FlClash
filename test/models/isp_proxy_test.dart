import 'dart:convert';

import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/models/models.dart';
import 'package:test/test.dart';

void main() {
  group('IspEndpoint.tryParse', () {
    test('reads a socks5 URL with percent-encoded credentials', () {
      final endpoint = IspEndpoint.tryParse(
        'socks5://us%40er:p%3Ass@1.2.3.4:45001',
      )!;
      expect(endpoint.type, 'socks5');
      expect(endpoint.server, '1.2.3.4');
      expect(endpoint.port, 45001);
      expect(endpoint.username, 'us@er');
      expect(endpoint.password, 'p:ss');
      expect(endpoint.tls, isFalse);
    });

    test('maps https to an http proxy with TLS', () {
      final endpoint = IspEndpoint.tryParse('https://proxy.example:443')!;
      expect(endpoint.type, 'http');
      expect(endpoint.port, 443);
      expect(endpoint.tls, isTrue);
      expect(endpoint.username, isEmpty);
      expect(IspEndpoint.tryParse('http://proxy.example')!.port, 80);
    });

    test('treats scheme-less forms as socks5', () {
      final colon = IspEndpoint.tryParse('1.2.3.4:45001:user:pa:ss')!;
      expect(colon.type, 'socks5');
      expect(colon.username, 'user');
      expect(colon.password, 'pa:ss');

      final at = IspEndpoint.tryParse('user:pass@1.2.3.4:45001')!;
      expect(at.type, 'socks5');
      expect(at.password, 'pass');

      expect(IspEndpoint.tryParse(' 1.2.3.4:1080 ')!.port, 1080);

      final atInPassword = IspEndpoint.tryParse('1.2.3.4:45001:user:p@ss')!;
      expect(atInPassword.server, '1.2.3.4');
      expect(atInPassword.password, 'p@ss');
    });

    test('rejects what is not an address', () {
      for (final input in [
        '',
        'host',
        'host:port',
        '1.2.3.4:70000',
        '1.2.3.4:1080:user',
        'vmess://1.2.3.4:1080',
        'socks5://1.2.3.4',
      ]) {
        expect(IspEndpoint.tryParse(input), isNull, reason: input);
      }
    });
  });

  test('ispRuleOf completes bare domains and rules without a target', () {
    expect(ispRuleOf('openai.com', 'ISP'), 'DOMAIN-SUFFIX,openai.com,ISP');
    expect(ispRuleOf('DOMAIN,a.com', 'ISP'), 'DOMAIN,a.com,ISP');
    expect(
      ispRuleOf('IP-CIDR,1.2.3.0/24,no-resolve', 'ISP'),
      'IP-CIDR,1.2.3.0/24,ISP,no-resolve',
    );
    expect(ispRuleOf('  ', 'ISP'), isNull);
    expect(
      ispRuleOf('https://chatgpt.com/c/1', 'ISP'),
      'DOMAIN-SUFFIX,chatgpt.com,ISP',
    );
    expect(ispRuleOf('*.openai.com', 'ISP'), 'DOMAIN-SUFFIX,openai.com,ISP');
    expect(ispRuleOf('FOO,bar', 'ISP'), isNull);
    expect(ispRuleOf('DST-PORT,abc', 'ISP'), isNull);
    expect(ispRuleOf('MATCH,Proxy', 'ISP'), isNull);
    expect(ispRuleOf('domain,a.com', 'ISP'), 'DOMAIN,a.com,ISP');
    expect(ispRuleOf('RULE-SET,ai', 'ISP'), isNull);
    expect(
      ispRuleOf(
        'RULE-SET,ai',
        'ISP',
        rawConfig: {
          'rule-providers': {'ai': <String, dynamic>{}},
        },
      ),
      'RULE-SET,ai,ISP',
    );
  });

  group('IspProxy.inject', () {
    Map<String, dynamic> profile() => {
      'proxies': <Object?>[
        {'name': 'HK', 'type': 'ss'},
      ],
      'proxy-groups': <Object?>[
        {
          'name': 'Select',
          'type': 'select',
          'proxies': ['HK'],
        },
      ],
      'proxy-providers': {'sub': <String, dynamic>{}},
    };

    const isp = IspProxy(
      enable: true,
      address: 'socks5://u:p@1.2.3.4:45001',
      rules: ['openai.com'],
    );

    test('replaces the rules with the ISP split around the node group', () {
      final raw = profile();
      final rules = isp.inject(raw, ['MATCH,Select']);

      expect(rules.first, 'DOMAIN-SUFFIX,openai.com,ISP');
      expect(rules, containsAll(['GEOSITE,cn,DIRECT', 'GEOIP,CN,DIRECT']));
      expect(rules, contains('IP-CIDR,160.79.104.0/23,ISP,no-resolve'));
      expect(
        rules.indexOf('IP-CIDR,160.79.104.0/23,ISP,no-resolve'),
        lessThan(rules.indexOf('GEOIP,CN,DIRECT')),
      );
      expect(rules.last, 'MATCH,$ispRelayGroupName');
      expect(rules, isNot(contains('MATCH,Select')));
      expect((raw['proxies'] as List).last, {
        'name': ispProxyName,
        'type': 'socks5',
        'server': '1.2.3.4',
        'port': 45001,
        'username': 'u',
        'password': 'p',
        'dialer-proxy': ispRelayGroupName,
      });
      expect((raw['proxy-groups'] as List).last, {
        'name': ispRelayGroupName,
        'type': 'select',
        'proxies': ['Select', 'HK', 'DIRECT'],
        'use': ['sub'],
      });
    });

    test('keeps groups that pull in every proxy out of the relay', () {
      final raw = profile();
      (raw['proxy-groups'] as List).addAll([
        {'name': 'Auto', 'type': 'url-test', 'include-all': true},
        {
          'name': 'Pick',
          'type': 'select',
          'proxies': ['Auto'],
        },
      ]);
      isp.inject(raw, const []);

      expect(
        ((raw['proxy-groups'] as List).last as Map)['proxies'],
        ['Select', 'HK', 'DIRECT'],
      );
    });

    test('changes nothing when disabled, unparsable or the name is taken', () {
      for (final setting in [
        isp.copyWith(enable: false),
        isp.copyWith(address: 'nonsense'),
      ]) {
        final raw = profile();
        expect(setting.inject(raw, ['MATCH,Select']), ['MATCH,Select']);
        expect(raw, profile());
      }

      final taken = profile();
      (taken['proxies'] as List).add({'name': ispProxyName, 'type': 'http'});
      final before = jsonEncode(taken);
      expect(isp.inject(taken, const []), isEmpty);
      expect(jsonEncode(taken), before);
    });
  });

  group('always direct', () {
    Map<String, dynamic> raw() => {
      'dns': <String, dynamic>{
        'fake-ip-filter': <Object?>['*.lan'],
      },
    };

    test('goes ahead of the rules and resolves through the system', () {
      const config = PatchClashConfig(
        alwaysDirect: ['https://git.example.cn/group', 'DOMAIN,a.example.cn'],
      );
      final profile = raw();
      final rules = config.applyAlwaysDirect(profile, ['MATCH,Proxy']);

      expect(rules, [
        'DOMAIN-SUFFIX,git.example.cn,DIRECT',
        'DOMAIN,a.example.cn,DIRECT',
        'MATCH,Proxy',
      ]);
      expect(config.effectiveMode, Mode.rule);
      final dns = profile['dns'] as Map;
      expect(dns['fake-ip-filter'], ['*.lan', '+.git.example.cn']);
      expect(dns['nameserver-policy'], {'+.git.example.cn': 'system://'});
    });

    test('runs global mode as rules that end at GLOBAL', () {
      const config = PatchClashConfig(
        mode: Mode.global,
        alwaysDirect: ['git.example.cn'],
      );
      expect(config.effectiveMode, Mode.rule);
      expect(config.applyAlwaysDirect(raw(), ['MATCH,Proxy']), [
        'DOMAIN-SUFFIX,git.example.cn,DIRECT',
        'MATCH,GLOBAL',
      ]);
    });

    test('changes nothing while the list is empty', () {
      const config = PatchClashConfig(mode: Mode.global);
      final profile = raw();
      expect(config.applyAlwaysDirect(profile, ['MATCH,Proxy']), [
        'MATCH,Proxy',
      ]);
      expect(config.effectiveMode, Mode.global);
      expect(profile, raw());
    });
  });

  test('process lookup is on only while the ISP proxy is', () {
    const off = PatchClashConfig();
    expect(off.effectiveFindProcessMode, FindProcessMode.off);
    expect(
      off.copyWith(ispProxy: const IspProxy(enable: true))
          .effectiveFindProcessMode,
      FindProcessMode.always,
    );
  });

  test('PatchClashConfig keeps the ISP proxy through JSON', () {
    const config = PatchClashConfig(
      ispProxy: IspProxy(
        enable: true,
        address: '1.2.3.4:1080',
        restoreMode: Mode.global,
      ),
    );
    final decoded = PatchClashConfig.fromJson(
      jsonDecode(jsonEncode(config.toJson())) as Map<String, Object?>,
    );
    expect(decoded.ispProxy, config.ispProxy);
    expect(
      PatchClashConfig.fromJson(const {}).ispProxy.rules,
      defaultIspProxyRules,
    );
  });
}
