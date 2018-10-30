<?php

namespace EricSource\QcloudCos;

use Illuminate\Support\ServiceProvider;

class QcloudCosProvider extends ServiceProvider
{
    public function boot()
    {
        // 复制自定义的文件到config目录
        if (!file_exists(config_path('qcloud-cos.php'))) {
            $this->publishes([
                dirname(__DIR__) . '/config/qcloud-cos.php' => config_path('qcloud-cos.php'),
            ], 'config');
        }
    }

    public function register()
    {
        $this->mergeConfigFrom(
            dirname(__DIR__) . '/config/qcloud-cos.php', 'qcloud-cos'
        );
    }
}