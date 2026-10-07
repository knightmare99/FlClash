import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/providers/providers.dart';
import 'package:fl_clash/widgets/widgets.dart';
import 'package:material_ui/material_ui.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

ProviderListenable<T> _ispSelector<T>(T Function(IspProxy isp) select) {
  return patchClashConfigProvider.select((state) => select(state.ispProxy));
}

ConfigWriter<T> _ispWriter<T>(
  PatchClashConfig Function(PatchClashConfig state, T value) update,
) {
  return (ref, value) => ref
      .read(patchClashConfigProvider.notifier)
      .update((state) => update(state, value));
}

void _setIspProxyEnabled(WidgetRef ref, bool enable) {
  final config = ref.read(patchClashConfigProvider);
  if (config.ispProxy.enable == enable) {
    return;
  }
  if (enable && IspEndpoint.tryParse(config.ispProxy.address) == null) {
    dialogs.showNotifier(currentAppLocalizations.ispProxyAddressTip);
    return;
  }
  final selectedMap = ref.read(selectedMapProvider);
  final globalName = GroupName.GLOBAL.name;
  final from = enable ? globalName : ispRelayGroupName;
  final to = enable ? ispRelayGroupName : globalName;
  final selected = selectedMap[from];
  if (selected != null &&
      selected != ispProxyName &&
      selected != ispRelayGroupName) {
    ref
        .read(profilesActionProvider.notifier)
        .updateCurrentSelectedMap(to, selected);
  }
  ref
      .read(patchClashConfigProvider.notifier)
      .update(
        (state) => state.copyWith.ispProxy(
          enable: enable,
          restoreMode: enable ? state.mode : null,
        ),
      );
  final setupAction = ref.read(setupActionProvider.notifier);
  setupAction.changeMode(
    enable ? Mode.rule : config.ispProxy.restoreMode ?? config.mode,
  );
  setupAction.applyProfileDebounce(silence: true);
}

class IspProxyView extends ConsumerStatefulWidget {
  const IspProxyView({super.key});

  @override
  ConsumerState<IspProxyView> createState() => _IspProxyViewState();
}

class _IspProxyViewState extends ConsumerState<IspProxyView> {
  late SetupAction _setupAction;

  @override
  void initState() {
    super.initState();
    _setupAction = ref.read(setupActionProvider.notifier);
  }

  @override
  void dispose() {
    _setupAction.autoApplyProfile();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final appLocalizations = context.appLocalizations;
    return BaseScaffold(
      title: appLocalizations.ispProxy,
      body: ListView(
        padding: const EdgeInsets.symmetric(
          horizontal: 16,
        ).copyWith(top: context.contentTopPadding, bottom: 16),
        children: [
          generateSectionV3(
            items: [
              ConfigToggleItem(
                title: (l) => l.ispProxy,
                subtitle: (l) => l.ispProxyDesc,
                selector: _ispSelector((isp) => isp.enable),
                onChanged: _setIspProxyEnabled,
              ),
              ConfigTextItem(
                title: (l) => l.ispProxyAddress,
                subtitle: (l) => l.ispProxyAddressDesc,
                showValueAsSubtitle: false,
                selector: _ispSelector((isp) => isp.address),
                onChanged: _ispWriter(
                  (state, value) => state.copyWith.ispProxy(address: value),
                ),
                maxLength: TextInputLimits.uri,
                keyboardType: TextInputType.url,
                normalize: (value) => value.trim(),
                validator: (value, l) =>
                    IspEndpoint.tryParse(value ?? '') == null
                    ? l.ispProxyAddressTip
                    : null,
              ),
              ConfigListEditItem(
                title: (l) => l.ispProxyRules,
                selector: _ispSelector((isp) => isp.rules),
                onChanged: _ispWriter(
                  (state, value) => state.copyWith.ispProxy(rules: value),
                ),
                itemMaxLength: TextInputLimits.rule,
              ),
            ],
          ),
        ],
      ),
    );
  }
}
