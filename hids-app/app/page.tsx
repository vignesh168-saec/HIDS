import OSSwitcher from "@/components/OSSwitcher";
import UploadInventory from "@/components/UploadInventory";

export default function Home() {
  return (
    <div className="font-sans min-h-screen p-8 sm:p-16 max-w-3xl mx-auto">
      <header className="mb-10">
        <h1 className="text-3xl font-semibold">Host Inventory Collector</h1>
        <p className="text-neutral-500 mt-2">
          Download and run a script to generate a system inventory on Windows or Linux.
        </p>
      </header>

      <section className="space-y-6">
        <OSSwitcher />
        <UploadInventory />

        <div className="rounded-lg border border-black/10 dark:border-white/15 p-5">
          <h2 className="text-xl font-medium mb-3">What the script collects</h2>
          <ul className="list-disc list-inside text-sm space-y-1">
            <li>Configuration files: <code>*.config</code>, <code>*.conf</code>, <code>*.yaml</code>, <code>*.xml</code>, <code>*.json</code></li>
            <li>Running processes with SHA256 hashes</li>
            <li>System services and their binary hashes</li>
            <li>Cron jobs (Linux) or Scheduled Tasks (Windows)</li>
            <li>Files in the Downloads folder with SHA256</li>
          </ul>
        </div>

        <div className="text-xs text-neutral-500">
          Tip: For integrity, compute and record the script&apos;s SHA256 before running.
        </div>
      </section>
    </div>
  );
}
