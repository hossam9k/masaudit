package com.demo
import kotlin.random.Random.Default.nextInt
import kotlin.random.Random
val notificationId = Random.nextInt()
fun open() = PendingIntent.getActivity(ctx, Random.nextInt(), intent, FLAGS)
val jitter = 0.75 + Math.random() * 0.5
suspend fun later() = delay(Random.nextLong(MIN_DELAY_MS, MAX_DELAY_MS))
@Composable fun Markdown() { val vmKey = rememberSaveable { Random.nextInt().toString() } }
val rng = Random(1337)
fun shuffle(day: Int) = items.shuffle(Random(day))
@Preview
@Composable
private fun BackupKeyScreenPreview() { val backupKey = (0 until 64).map { Random.nextInt(65..90).toChar() } }
