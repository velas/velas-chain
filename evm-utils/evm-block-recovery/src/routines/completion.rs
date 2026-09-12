use {
    crate::{
        cli::{Cli, CompletionArgs},
        error::RoutineResult,
    },
    clap::CommandFactory,
};

pub fn completion(args: CompletionArgs) -> RoutineResult {
    clap_complete::generate(
        args.shell,
        &mut Cli::command(),
        "evm-block-recovery",
        &mut std::io::stdout(),
    );

    Ok(())
}

// zsh:
// sudo evm-block-recovery completion --shell zsh > /usr/share/zsh/site-functions/_evm-block-recovery
// sudo chown root:root /usr/share/zsh/site-functions/_evm-block-recovery
// sudo chmod 0644 /usr/share/zsh/site-functions/_evm-block-recovery

// bash:
// sudo apt-get install bash-completion
// sudo mkdir /etc/bash_completion.d/
// sudo evm-block-recovery completion --shell bash > /etc/bash_completion.d/evm-block-recovery.bash
