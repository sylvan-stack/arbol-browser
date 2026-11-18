import { mountProfileNavigation } from './navigation.mjs';

const ui = mountProfileNavigation(document.querySelector('#navigation'), {
  onAction: request => window.arbolPreview.action(request),
});
window.arbolPreview.onState(ui.update);
window.arbolPreview.state().then(ui.update, () => ui.error('Could not read the Browser profiles.'));
