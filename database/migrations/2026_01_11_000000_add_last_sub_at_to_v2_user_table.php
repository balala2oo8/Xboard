<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::table('v2_user', function (Blueprint $table) {
            $table->integer('last_sub_at')->nullable()->after('last_login_at')->comment('最后更新订阅时间');
        });
    }

    /**
     * Down the migrations.
     */
    public function down(): void
    {
        Schema::table('v2_user', function (Blueprint $table) {
            $table->dropColumn('last_sub_at');
        });
    }
};
