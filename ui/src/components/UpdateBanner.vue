<script setup lang="ts">
import { useI18n } from 'vue-i18n';
import { useUpdateStore } from '@/stores/update';

const update = useUpdateStore();
const { t } = useI18n();
</script>

<template>
  <div v-if="update.shouldNotify && update.info" class="update-banner">
    <span class="dot" />
    <span class="text">
      {{ t('update.banner', { version: update.info.version }) }}
    </span>
    <a-button type="link" size="small" @click="update.openModal()">
      {{ t('update.viewDetail') }}
    </a-button>
    <a-button type="text" size="small" class="close" @click="update.dismiss()">
      {{ t('update.later') }}
    </a-button>
  </div>
</template>

<style scoped>
.update-banner {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 12px;
  margin-bottom: 12px;
  border-radius: 8px;
  border: 1px solid color-mix(in srgb, var(--accent, #1677ff) 40%, transparent);
  background: color-mix(in srgb, var(--accent, #1677ff) 8%, transparent);
  font-size: 13px;
}

.dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--accent, #1677ff);
  flex-shrink: 0;
}

.text {
  flex: 1;
}

.close {
  color: var(--text-secondary, #888);
}
</style>
